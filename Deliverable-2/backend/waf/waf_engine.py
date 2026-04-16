"""
waf_engine.py — Main WAF Pipeline Orchestrator

This is the single entry point for processing any HTTP request through the
WAF + IDS pipeline.  All other modules are pure functions / strategies;
this module wires them together in the correct order.

Pipeline:
  1. Ingress       (ingress.py)
  2. Normalisation (normalizer.py)
  3. Feature extraction (extractor.py)
  4. Detection engines (detection/)
  5. Scoring       (scoring.py)
  6. Decision      (decision.py)
  7. Response      (response.py)
  8. Logging       (logger.py)

Usage (from Flask app.py):
    from waf_engine import WAFEngine
    waf = WAFEngine()

    @app.before_request
    def waf_check():
        result = waf.process(request)
        if result is not None:
            return result   # blocked response

Integration notes:
  - call waf.record_response_status(request_id, status_code) AFTER
    the backend responds to feed 404/401 data into the behavioral engine.
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

from flask import Request, Response

from config import config
from ingress import build_ingress_request, IngressRequest
from normalizer import normalise
from extractor import extract_features
from detection import DetectionReport, DetectorRegistry
from detection.rule_engine import RuleEngine
from detection.behavioral import BehavioralEngine, record_404, record_auth_failure
from detection.ml_interface import MLEngine, AnomalyEngine
from scoring import compute_score
from decision import decide, Action
from response import build_response
from logger import (
    init_logging,
    get_logger,
    build_access_log,
    build_attack_log,
    log_access_event,
    log_attack_event,
)

logger = get_logger("waf_engine")


class WAFEngine:
    """
    Thread-safe WAF engine singleton.

    The DetectorRegistry is immutable after __init__; all state lives
    in the individual detection engines.  This class is safe to share
    across Flask worker threads.
    """

    def __init__(self):
        init_logging()
        self._registry = DetectorRegistry()

        # Register detection engines in priority order
        if config.enable_rule_engine:
            self._registry.register(RuleEngine())
            logger.info("Rule engine registered")

        if config.enable_behavioral_engine:
            self._registry.register(BehavioralEngine())
            logger.info("Behavioral engine registered")

        # ML engine: registered always; is_available() returns False when disabled
        ml_engine = MLEngine()
        self._registry.register(ml_engine)
        if config.enable_ml_engine:
            logger.info("ML engine registered (enabled)")
        else:
            logger.info("ML engine registered (disabled — enable via config.ml.enabled)")

        # Anomaly engine: same pattern
        anomaly_engine = AnomalyEngine()
        self._registry.register(anomaly_engine)
        if config.enable_anomaly_engine:
            logger.info("Anomaly engine registered (enabled)")
        else:
            logger.info(
                "Anomaly engine registered (disabled — enable via config.anomaly.enabled "
                "after fitting a baseline)"
            )

        logger.info(
            "WAFEngine initialised in %s mode (fail_%s)",
            config.environment,
            "open" if config.fail_open else "closed",
        )

    # ----------------------------------------------------------------
    # Main pipeline entry point
    # ----------------------------------------------------------------

    def process(self, flask_req: Request) -> Optional[Response]:
        """
        Run the full WAF pipeline for an incoming Flask request.

        Returns:
          - Flask Response if the request should be blocked/challenged.
          - None if the request should be passed through to the backend.

        Never raises — all exceptions are caught and handled according to
        the fail_open / fail_closed policy.
        """
        start = time.perf_counter()
        request_id = str(uuid.uuid4())

        try:
            return self._run_pipeline(flask_req, request_id, start)
        except Exception as exc:
            logger.error(
                "WAF pipeline error for %s: %s",
                request_id[:8],
                exc,
                exc_info=True,
            )
            if config.fail_open:
                logger.warning("Fail-open: allowing request %s after error", request_id[:8])
                return None
            else:
                # Fail-closed: block the request on internal error
                from flask import jsonify
                resp = jsonify({"error": "service_unavailable", "code": 503})
                resp.status_code = 503
                return resp

    def _run_pipeline(
        self,
        flask_req: Request,
        request_id: str,
        start: float,
    ) -> Optional[Response]:
        # ---- Step 1: Ingress ----
        ingress = build_ingress_request(flask_req, request_id)

        # Quick-path: IP blocklist (skip full pipeline)
        if ingress.ip_blocklisted and not ingress.ip_allowlisted:
            return self._block_fast(ingress, "IP blocklisted", start)

        # ---- Step 2: Normalisation ----
        nr = normalise(ingress)

        # ---- Step 3: Feature extraction ----
        fv = extract_features(nr)

        # ---- Step 4: Detection engines ----
        report = DetectionReport(request_id=request_id)
        self._registry.run_all(nr, fv, report)

        # Log engine errors (non-fatal)
        if report.engine_errors:
            for engine, err in report.engine_errors.items():
                logger.error("Detection engine '%s' error: %s", engine, err)

        # ---- Step 5: Scoring ----
        risk = compute_score(report, fv, ingress)

        # ---- Step 6: Decision ----
        decision = decide(risk, ingress)

        # ---- Step 7: Response ----
        blocking_response = build_response(decision)

        # ---- Step 8: Logging ----
        duration_ms = (time.perf_counter() - start) * 1000
        self._log_event(ingress, decision, nr, duration_ms)

        return blocking_response  # None = allow through

    def _block_fast(
        self,
        ingress: IngressRequest,
        reason: str,
        start: float,
    ) -> Response:
        """Quick block path — skips the full pipeline for known-bad IPs."""
        from scoring import RiskScore
        from decision import WAFDecision, Action
        from flask import jsonify

        risk = RiskScore(request_id=ingress.request_id, score=1.0, ip_blocklisted=True)
        decision = WAFDecision(
            action=Action.BLOCK,
            reason=reason,
            risk_score=risk,
            request_id=ingress.request_id,
            http_status=403,
        )
        duration_ms = (time.perf_counter() - start) * 1000
        self._log_fast_block(ingress, decision, duration_ms)
        resp = jsonify({"error": "forbidden", "message": "Request blocked.", "code": 403})
        resp.status_code = 403
        return resp

    # ----------------------------------------------------------------
    # Post-response feedback hooks (called from app.py after_request)
    # ----------------------------------------------------------------

    def on_response(
        self,
        request_id: str,
        client_ip: str,
        http_status: int,
    ) -> None:
        """
        Called after the backend returns a response.
        Feeds 404 / 401 signals into the behavioral engine.
        """
        if http_status == 404:
            record_404(client_ip)
        elif http_status in (401, 403):
            record_auth_failure(client_ip)

    # ----------------------------------------------------------------
    # Logging helpers
    # ----------------------------------------------------------------

    def _log_event(self, ingress, decision, nr, duration_ms: float) -> None:
        if decision.action in (Action.BLOCK, Action.RATE_LIMIT, Action.CHALLENGE):
            event = build_attack_log(ingress, decision, nr, duration_ms)
            log_attack_event(event)
        else:
            event = build_access_log(ingress, decision, duration_ms)
            log_access_event(event)

    def _log_fast_block(self, ingress, decision, duration_ms: float) -> None:
        event = {
            "event_type": "attack",
            "request_id": ingress.request_id,
            "client_ip": ingress.client_ip,
            "method": ingress.method,
            "path": ingress.path,
            "action": "BLOCK",
            "reason": decision.reason,
            "risk_score": 1.0,
            "risk_label": "CRITICAL",
            "duration_ms": round(duration_ms, 2),
            "fast_path": True,
        }
        log_attack_event(event)

    # ----------------------------------------------------------------
    # Engine management (admin API hooks)
    # ----------------------------------------------------------------

    def reload_rules(self) -> dict:
        """Hot-reload rule engine (admin API)."""
        from ingress import reload_ip_lists
        reload_ip_lists()
        logger.info("IP lists reloaded via admin API")
        return {"status": "ok", "message": "IP lists reloaded"}

    def get_engine_status(self) -> dict:
        return {
            "rule_engine": config.enable_rule_engine,
            "behavioral_engine": config.enable_behavioral_engine,
            "ml_engine": config.enable_ml_engine,
            "anomaly_engine": config.enable_anomaly_engine,
            "fail_open": config.fail_open,
            "environment": config.environment,
        }
