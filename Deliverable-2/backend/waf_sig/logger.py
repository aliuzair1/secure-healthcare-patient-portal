"""
logger.py — Structured JSON Logging

Every WAF event is written as a machine-readable JSON line to one of three
rotating files:

  logs/access.log  — every allowed request
  logs/attack.log  — every blocked / challenged request
  logs/error.log   — internal WAF errors

Lines are directly ingestible by Filebeat → Elasticsearch / Wazuh / Splunk
with no pre-processing required.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# JSON formatter  —  each log record becomes a single JSON line
# ---------------------------------------------------------------------------

class _JSONFormatter(logging.Formatter):
    _SKIP = frozenset([
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process", "message",
    ])

    def format(self, record: logging.LogRecord) -> str:
        obj: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in self._SKIP:
                continue
            try:
                json.dumps(v)
                obj[k] = v
            except (TypeError, ValueError):
                obj[k] = str(v)
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj, default=str)


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

_module_loggers:  Dict[str, logging.Logger] = {}
_access_logger:   Optional[logging.Logger]  = None
_attack_logger:   Optional[logging.Logger]  = None
_initialised:     bool = False


def _make_handler(path: str, max_bytes: int, backup_count: int) -> logging.Handler:
    h = logging.handlers.RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    h.setFormatter(_JSONFormatter())
    return h


# ---------------------------------------------------------------------------
# Public init  —  call once at startup (idempotent)
# ---------------------------------------------------------------------------

def init_logging() -> None:
    global _initialised, _access_logger, _attack_logger
    if _initialised:
        return

    from config import config as waf_config
    cfg = waf_config.logging
    os.makedirs(cfg.log_dir, exist_ok=True)

    # Root WAF logger (console for dev + rotating error file)
    root = logging.getLogger("waf")
    root.setLevel(logging.DEBUG if waf_config.debug else logging.INFO)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_JSONFormatter())
    console.setLevel(logging.DEBUG if waf_config.debug else logging.WARNING)
    root.addHandler(console)

    err_handler = _make_handler(cfg.error_log, cfg.max_bytes, cfg.backup_count)
    err_handler.setLevel(logging.ERROR)
    root.addHandler(err_handler)

    # Dedicated access log (separate logger — no propagation to root)
    _access_logger = logging.getLogger("waf.access")
    _access_logger.setLevel(logging.INFO)
    _access_logger.propagate = False
    _access_logger.addHandler(_make_handler(cfg.access_log, cfg.max_bytes, cfg.backup_count))

    # Dedicated attack log
    _attack_logger = logging.getLogger("waf.attack")
    _attack_logger.setLevel(logging.INFO)
    _attack_logger.propagate = False
    _attack_logger.addHandler(_make_handler(cfg.attack_log, cfg.max_bytes, cfg.backup_count))

    _initialised = True


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_logger(name: str) -> logging.Logger:
    """Return a module logger under the 'waf' namespace."""
    key = f"waf.{name}"
    if key not in _module_loggers:
        _module_loggers[key] = logging.getLogger(key)
    return _module_loggers[key]


def log_access(event: Dict[str, Any]) -> None:
    if _access_logger is None:
        init_logging()
    _access_logger.info("access", extra=event)   # type: ignore[arg-type]


def log_attack(event: Dict[str, Any]) -> None:
    if _attack_logger is None:
        init_logging()
    _attack_logger.warning("attack", extra=event)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Event builders  —  called by waf_engine after the decision is made
# ---------------------------------------------------------------------------

def build_access_event(ingress, decision, duration_ms: float) -> Dict[str, Any]:
    from config import config as waf_config
    risk = decision.risk_score
    ev: Dict[str, Any] = {
        "event_type":  "access",
        "request_id":  ingress.request_id,
        "client_ip":   ingress.client_ip,
        "method":      ingress.method,
        "host":        ingress.host,
        "path":        ingress.path,
        "query":       ingress.query_string[:512],
        "action":      decision.action.value,
        "risk_score":  round(risk.score, 4),
        "risk_label":  risk.risk_label,
        "duration_ms": round(duration_ms, 2),
        "user_agent":  ingress.user_agent[:256],
        "content_type":ingress.content_type,
        "body_bytes":  ingress.content_length,
    }
    cfg = waf_config.logging
    if cfg.log_request_body and ingress.raw_body:
        ev["body_snippet"] = ingress.raw_body[:cfg.max_body_log_bytes].decode("utf-8", "replace")
    return ev


def build_attack_event(ingress, decision, nr, duration_ms: float) -> Dict[str, Any]:
    risk = decision.risk_score
    return {
        "event_type":          "attack",
        "request_id":          ingress.request_id,
        "client_ip":           ingress.client_ip,
        "method":              ingress.method,
        "host":                ingress.host,
        "path":                ingress.path,
        "query":               ingress.query_string[:512],
        "action":              decision.action.value,
        "reason":              decision.reason,
        "risk_score":          round(risk.score, 4),
        "risk_label":          risk.risk_label,
        "matched_categories":  risk.matched_categories,
        "rule_ids":            decision.rule_ids_fired,
        "top_findings": [
            {
                "rule_id":  f.rule_id,
                "category": f.category.value,
                "score":    round(f.score, 4),
                "details":  f.details,
            }
            for f in risk.top_findings
        ],
        "obfuscation_detected": risk.obfuscation_detected,
        "known_attack_tool":    risk.known_attack_tool,
        "encoding_depth":       getattr(nr, "encoding_depth", 0),
        "duration_ms":          round(duration_ms, 2),
        "user_agent":           ingress.user_agent[:256],
        "body_bytes":           ingress.content_length,
    }
