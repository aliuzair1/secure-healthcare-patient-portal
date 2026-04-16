"""logger.py — Structured JSON Logging"""
from __future__ import annotations
import json, logging, logging.handlers, os, sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

class JSONFormatter(logging.Formatter):
    def format(self, record):
        obj = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        skip = {"name","msg","args","levelname","levelno","pathname","filename","module",
                "exc_info","exc_text","stack_info","lineno","funcName","created","msecs",
                "relativeCreated","thread","threadName","processName","process","message"}
        for k, v in record.__dict__.items():
            if k not in skip:
                try:
                    json.dumps(v)
                    obj[k] = v
                except (TypeError, ValueError):
                    obj[k] = str(v)
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj, default=str)

_loggers: Dict[str, logging.Logger] = {}
_access_logger: Optional[logging.Logger] = None
_attack_logger: Optional[logging.Logger] = None
_initialised = False

def _ensure_log_dir(d):
    os.makedirs(d, exist_ok=True)

def _build_handler(filepath, max_bytes, backup_count):
    h = logging.handlers.RotatingFileHandler(filepath, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
    h.setFormatter(JSONFormatter())
    return h

def init_logging(log_config=None):
    global _initialised, _access_logger, _attack_logger
    if _initialised:
        return
    from config import config as waf_config
    cfg = log_config or waf_config.logging
    _ensure_log_dir(cfg.log_dir)
    root = logging.getLogger("waf")
    root.setLevel(logging.DEBUG if waf_config.debug else logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(JSONFormatter())
    console.setLevel(logging.DEBUG if waf_config.debug else logging.WARNING)
    root.addHandler(console)
    eh = _build_handler(cfg.error_log, cfg.max_bytes, cfg.backup_count)
    eh.setLevel(logging.ERROR)
    root.addHandler(eh)
    _access_logger = logging.getLogger("waf.access")
    _access_logger.setLevel(logging.INFO)
    _access_logger.propagate = False
    _access_logger.addHandler(_build_handler(cfg.access_log, cfg.max_bytes, cfg.backup_count))
    _attack_logger = logging.getLogger("waf.attack")
    _attack_logger.setLevel(logging.INFO)
    _attack_logger.propagate = False
    _attack_logger.addHandler(_build_handler(cfg.attack_log, cfg.max_bytes, cfg.backup_count))
    _initialised = True

def get_logger(name):
    full = f"waf.{name}"
    if full not in _loggers:
        _loggers[full] = logging.getLogger(full)
    return _loggers[full]

def log_access_event(event):
    if _access_logger is None: init_logging()
    _access_logger.info("access", extra=event)

def log_attack_event(event):
    if _attack_logger is None: init_logging()
    _attack_logger.warning("attack", extra=event)

def build_access_log(ingress, decision, duration_ms):
    from config import config as waf_config
    risk = decision.risk_score
    e = {
        "event_type": "access",
        "request_id": ingress.request_id,
        "client_ip": ingress.client_ip,
        "method": ingress.method,
        "host": ingress.host,
        "path": ingress.path,
        "query": ingress.query_string[:512],
        "status": decision.http_status,
        "action": decision.action.value,
        "risk_score": round(risk.score, 4),
        "risk_label": risk.risk_label,
        "duration_ms": round(duration_ms, 2),
        "user_agent": ingress.user_agent[:256],
    }
    if waf_config.logging.log_request_body and ingress.raw_body:
        e["body_snippet"] = ingress.raw_body[:waf_config.logging.max_body_log_bytes].decode("utf-8","replace")
    return e

def build_attack_log(ingress, decision, nr, duration_ms):
    risk = decision.risk_score
    findings_data = [
        {"rule_id": f.rule_id, "category": f.category.value, "score": round(f.score, 4),
         "details": f.details, "engine": f.engine}
        for f in risk.top_findings
    ]
    return {
        "event_type": "attack",
        "request_id": ingress.request_id,
        "client_ip": ingress.client_ip,
        "method": ingress.method,
        "host": ingress.host,
        "path": ingress.path,
        "query": ingress.query_string[:512],
        "action": decision.action.value,
        "reason": decision.reason,
        "risk_score": round(risk.score, 4),
        "risk_label": risk.risk_label,
        "matched_categories": risk.matched_categories,
        "top_findings": findings_data,
        "rule_ids": decision.rule_ids_fired,
        "obfuscation_detected": risk.obfuscation_detected,
        "duration_ms": round(duration_ms, 2),
        "user_agent": ingress.user_agent[:256],
        "encoding_depth": getattr(nr, "encoding_depth", 0),
    }
