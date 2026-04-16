"""decision.py — Decision Engine"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Callable, Dict, List, Optional
from config import config
from logger import get_logger
logger = get_logger("decision")
thresholds = config.thresholds

class Action(str, Enum):
    ALLOW = "ALLOW"; BLOCK = "BLOCK"; RATE_LIMIT = "RATE_LIMIT"
    CHALLENGE = "CHALLENGE"; LOG_ONLY = "LOG_ONLY"

@dataclass
class WAFDecision:
    action: Action; reason: str; risk_score: object; request_id: str
    http_status: int = 200; retry_after_seconds: int = 0
    rule_ids_fired: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    def is_blocking(self): return self.action in (Action.BLOCK, Action.RATE_LIMIT, Action.CHALLENGE)

class PolicyOverrides:
    def __init__(self):
        self._path: Dict[str,Action] = {"/health":Action.ALLOW,"/healthz":Action.ALLOW,
                                         "/ready":Action.ALLOW,"/metrics":Action.LOG_ONLY}
        self._ip: Dict[str,Action] = {}
    def get_path_override(self, path):
        if path in self._path: return self._path[path]
        for p, a in self._path.items():
            if path.startswith(p): return a
        return None
    def get_ip_override(self, ip): return self._ip.get(ip)
    def set_path_override(self, path, action): self._path[path] = action
    def set_ip_override(self, ip, action): self._ip[ip] = action
    def remove_path_override(self, path): self._path.pop(path, None)
    def remove_ip_override(self, ip): self._ip.pop(ip, None)
    def list_overrides(self): return {"paths":{k:v.value for k,v in self._path.items()},
                                       "ips":{k:v.value for k,v in self._ip.items()}}

policy_overrides = PolicyOverrides()

def _make(action, reason, risk, request_id, rule_ids, http_status=200, retry_after=0):
    d = WAFDecision(action=action,reason=reason,risk_score=risk,request_id=request_id,
                    http_status=http_status if action!=Action.ALLOW else 200,
                    retry_after_seconds=retry_after,rule_ids_fired=rule_ids,
                    categories=risk.matched_categories)
    lvl = "warning" if d.is_blocking() else "debug"
    getattr(logger,lvl)("Decision [%s] action=%s score=%.3f reason='%s'",
                         request_id[:8],action.value,risk.score,reason)
    return d

def decide(risk, ingress) -> WAFDecision:
    rid = ingress.request_id
    rule_ids = [f.rule_id for f in risk.top_findings if f.matched]
    ip_ov = policy_overrides.get_ip_override(ingress.client_ip)
    if ip_ov: return _make(ip_ov, f"IP override → {ip_ov.value}", risk, rid, rule_ids)
    path_ov = policy_overrides.get_path_override(ingress.path)
    if path_ov: return _make(path_ov, f"Path override {ingress.path} → {path_ov.value}", risk, rid, rule_ids)
    if ingress.ip_allowlisted: return _make(Action.ALLOW,f"IP allowlisted: {ingress.client_ip}",risk,rid,rule_ids)
    if ingress.ip_blocklisted: return _make(Action.BLOCK,f"IP blocklisted: {ingress.client_ip}",risk,rid,rule_ids,http_status=403)
    if config.fail_open:
        a = Action.LOG_ONLY if risk.score >= thresholds.log_only else Action.ALLOW
        return _make(a, f"Fail-open score={risk.score:.3f}", risk, rid, rule_ids)
    s = risk.score
    if s >= thresholds.block: return _make(Action.BLOCK,f"Score {s:.3f} >= block {thresholds.block}",risk,rid,rule_ids,http_status=403)
    if s >= thresholds.challenge: return _make(Action.CHALLENGE,f"Score {s:.3f} >= challenge {thresholds.challenge}",risk,rid,rule_ids,http_status=403)
    if s >= thresholds.rate_limit: return _make(Action.RATE_LIMIT,f"Score {s:.3f} >= rate_limit {thresholds.rate_limit}",risk,rid,rule_ids,http_status=429,retry_after=30)
    if s >= thresholds.log_only: return _make(Action.LOG_ONLY,f"Score {s:.3f} >= log {thresholds.log_only}",risk,rid,rule_ids)
    return _make(Action.ALLOW,f"Score {s:.3f} below all thresholds",risk,rid,rule_ids)
