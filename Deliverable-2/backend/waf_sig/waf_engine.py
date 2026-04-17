"""
waf_engine.py — WAF Pipeline Orchestrator

The single entry point for processing every HTTP request.

6-step pipeline
---------------
  1. Ingress      — extract real IP, build IngressRequest
  2. Normalise    — decode, de-obfuscate
  3. Detect       — run all registered rule engines
  4. Score        — compute unified risk score
  5. Decide       — map score to Action
  6. Respond      — build blocking response (or None to pass through)
  + Log           — write structured JSON event to access / attack log

Flask integration (app.py)
--------------------------
  waf = WAFEngine()

  @app.before_request
  def waf_check():
      result = waf.process(request)
      if result is not None:
          return result   # short-circuit — backend never sees this request

  @app.after_request
  def strip_headers(response):
      response.headers.pop("Server", None)
      response.headers.pop("X-Powered-By", None)
      return response
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

from flask import Request, Response

from config import config
from ingress import build_ingress_request, reload_ip_lists
from normalizer import normalise
from detection import DetectionReport, DetectorRegistry
from detection.rule_engine import RuleEngine
from scoring import compute_score
from decision import decide, Action
from response import build_response
from logger import (
    init_logging,
    get_logger,
    build_access_event,
    build_attack_event,
    log_access,
    log_attack,
)

logger = get_logger("waf_engine")


class WAFEngine:
    """
    Thread-safe WAF engine.

    All detection state is stateless (signature matching only).
    Safe to share across Flask worker threads without locking.
    """

    def __init__(self):
        init_logging()
        self._registry = DetectorRegistry()
        self._registry.register(RuleEngine())
        logger.info(
            "WAFEngine ready — env=%s fail_open=%s",
            config.environment,
            config.fail_open,
        )

    # ----------------------------------------------------------------
    # Main entry point — called from Flask before_request
    # ----------------------------------------------------------------

    def process(self, flask_req: Request) -> Optional[Response]:
        """
        Run the full WAF pipeline for one request.

        Returns a Flask Response to block the request, or None to allow it
        through to the backend.

        Never raises — internal errors are handled according to fail_open policy.
        """
        start      = time.perf_counter()
        request_id = str(uuid.uuid4())

        try:
            return self._pipeline(flask_req, request_id, start)
        except Exception as exc:
            logger.error("Pipeline error for %s: %s", request_id[:8], exc, exc_info=True)
            if config.fail_open:
                logger.warning("fail-open: allowing request %s after error", request_id[:8])
                return None
            # fail-closed: block on internal error
            from flask import jsonify
            resp = jsonify({"error": "service_unavailable", "code": 503})
            resp.status_code = 503
            return resp

    def _pipeline(
        self,
        flask_req:  Request,
        request_id: str,
        start:      float,
    ) -> Optional[Response]:

        # ── Step 1: Ingress ──────────────────────────────────────────────
        ingress = build_ingress_request(flask_req, request_id)

        # Fast path: blocklisted IP — skip full pipeline
        if ingress.ip_blocklisted and not ingress.ip_allowlisted:
            return self._fast_block(ingress, "IP blocklisted", start)

        # Fast path: allowlisted IP — skip all detection
        if ingress.ip_allowlisted:
            logger.debug("Allowlisted IP %s — skipping detection", ingress.client_ip)
            return None

        # ── Step 2: Normalise ────────────────────────────────────────────
        nr = normalise(ingress)

        # ── Step 3: Detect ───────────────────────────────────────────────
        report = DetectionReport(request_id=request_id)
        self._registry.run_all(nr, report)

        for engine, err in report.engine_errors.items():
            logger.error("Engine '%s' error: %s", engine, err)

        # ── Step 4: Score ────────────────────────────────────────────────
        risk = compute_score(report, nr, ingress)

        # ── Step 5: Decide ───────────────────────────────────────────────
        decision = decide(risk, ingress)

        # ── Step 6: Respond ──────────────────────────────────────────────
        blocking = build_response(decision)

        # ── Log ──────────────────────────────────────────────────────────
        duration_ms = (time.perf_counter() - start) * 1000
        self._log(ingress, decision, nr, duration_ms)

        return blocking   # None → allow through to backend

    # ----------------------------------------------------------------
    # Fast-path block (no pipeline overhead)
    # ----------------------------------------------------------------

    def _fast_block(self, ingress, reason: str, start: float) -> Response:
        from scoring import RiskScore
        from decision import WAFDecision
        from flask import jsonify

        risk     = RiskScore(request_id=ingress.request_id, score=1.0, ip_blocklisted=True)
        decision = WAFDecision(
            action      = Action.BLOCK,
            reason      = reason,
            risk_score  = risk,
            request_id  = ingress.request_id,
            http_status = 403,
        )
        duration_ms = (time.perf_counter() - start) * 1000
        log_attack({
            "event_type": "attack",
            "request_id": ingress.request_id,
            "client_ip":  ingress.client_ip,
            "method":     ingress.method,
            "path":       ingress.path,
            "action":     "BLOCK",
            "reason":     reason,
            "risk_score": 1.0,
            "risk_label": "CRITICAL",
            "duration_ms":round(duration_ms, 2),
            "fast_path":  True,
        })
        resp = jsonify({"error": "forbidden", "message": "Request blocked.", "code": 403})
        resp.status_code = 403
        return resp

    # ----------------------------------------------------------------
    # Logging
    # ----------------------------------------------------------------

    def _log(self, ingress, decision, nr, duration_ms: float) -> None:
        if decision.is_blocking():
            log_attack(build_attack_event(ingress, decision, nr, duration_ms))
        else:
            log_access(build_access_event(ingress, decision, duration_ms))

    # ----------------------------------------------------------------
    # Admin API hooks
    # ----------------------------------------------------------------

    def reload(self) -> dict:
        """Hot-reload IP allowlist and blocklist from disk."""
        reload_ip_lists()
        return {"status": "ok", "message": "IP lists reloaded"}

    def status(self) -> dict:
        return {
            "engine":      "signature-based WAF",
            "environment": config.environment,
            "fail_open":   config.fail_open,
            "thresholds": {
                "block":      config.thresholds.block,
                "challenge":  config.thresholds.challenge,
                "rate_limit": config.thresholds.rate_limit,
                "log_only":   config.thresholds.log_only,
            },
        }
