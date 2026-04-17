"""
decision.py — Decision Engine (Pipeline Step 5)

Maps a RiskScore to an enforcement Action:

  ALLOW      — pass to backend (score below all thresholds)
  BLOCK      — 403 Forbidden
  CHALLENGE  — 403 + CAPTCHA / JS challenge hook
  RATE_LIMIT — 429 Too Many Requests + Retry-After
  LOG_ONLY   — allow but write to attack log (passive / audit mode)

Priority order (highest first)
-------------------------------
  1. IP allowlist  → always ALLOW
  2. IP blocklist  → always BLOCK
  3. Path / IP policy overrides  (admin API hot-injection)
  4. fail_open mode  (security degraded → LOG_ONLY instead of BLOCK)
  5. Score thresholds (configured in config.thresholds)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Callable, Dict, List, Optional

from config import config
from logger import get_logger

logger     = get_logger("decision")
thresholds = config.thresholds


# ---------------------------------------------------------------------------
# Action enum
# ---------------------------------------------------------------------------

class Action(str, Enum):
    ALLOW      = "ALLOW"
    BLOCK      = "BLOCK"
    RATE_LIMIT = "RATE_LIMIT"
    CHALLENGE  = "CHALLENGE"
    LOG_ONLY   = "LOG_ONLY"


# ---------------------------------------------------------------------------
# WAFDecision  —  complete verdict with audit metadata
# ---------------------------------------------------------------------------

@dataclass
class WAFDecision:
    action:              Action
    reason:              str
    risk_score:          object    # RiskScore (avoid circular import)
    request_id:          str
    http_status:         int            = 200
    retry_after_seconds: int            = 0
    rule_ids_fired:      List[str]      = field(default_factory=list)
    categories:          List[str]      = field(default_factory=list)

    def is_blocking(self) -> bool:
        return self.action in (Action.BLOCK, Action.RATE_LIMIT, Action.CHALLENGE)


# ---------------------------------------------------------------------------
# Policy override registry  —  path and IP level, admin API writable
# ---------------------------------------------------------------------------

class PolicyOverrides:
    """
    Runtime policy overrides.

    Pre-loaded with safe defaults (health endpoints always ALLOWed).
    The admin API can add / remove / list overrides without restart.
    """

    def __init__(self):
        self._paths: Dict[str, Action] = {
            "/health":   Action.ALLOW,
            "/healthz":  Action.ALLOW,
            "/ready":    Action.ALLOW,
            "/readyz":   Action.ALLOW,
            "/ping":     Action.ALLOW,
            "/metrics":  Action.LOG_ONLY,   # observe but don't block
        }
        self._ips: Dict[str, Action] = {}

    # ── Path overrides ──────────────────────────────────────────────────

    def get_path(self, path: str) -> Optional[Action]:
        if path in self._paths:
            return self._paths[path]
        for prefix, action in self._paths.items():
            if path.startswith(prefix):
                return action
        return None

    def set_path(self, path: str, action: Action) -> None:
        self._paths[path] = action

    def remove_path(self, path: str) -> None:
        self._paths.pop(path, None)

    # ── IP overrides ────────────────────────────────────────────────────

    def get_ip(self, ip: str) -> Optional[Action]:
        return self._ips.get(ip)

    def set_ip(self, ip: str, action: Action) -> None:
        self._ips[ip] = action

    def remove_ip(self, ip: str) -> None:
        self._ips.pop(ip, None)

    # ── Inspection ──────────────────────────────────────────────────────

    def list_all(self) -> Dict:
        return {
            "paths": {k: v.value for k, v in self._paths.items()},
            "ips":   {k: v.value for k, v in self._ips.items()},
        }


# Module-level singleton — used by app.py admin routes
policy_overrides = PolicyOverrides()


# ---------------------------------------------------------------------------
# Decision function
# ---------------------------------------------------------------------------

def decide(risk, ingress) -> WAFDecision:
    """
    Map a RiskScore + IngressRequest to a WAFDecision.

    Arguments:
        risk    — RiskScore from scoring.compute_score()
        ingress — IngressRequest from ingress.build_ingress_request()
    """
    rid      = ingress.request_id
    rule_ids = [f.rule_id for f in risk.top_findings if f.matched]

    # ── Priority 1: IP allowlist ────────────────────────────────────────
    if ingress.ip_allowlisted:
        return _make(Action.ALLOW, f"IP allowlisted: {ingress.client_ip}",
                     risk, rid, rule_ids)

    # ── Priority 2: IP blocklist ────────────────────────────────────────
    if ingress.ip_blocklisted:
        return _make(Action.BLOCK, f"IP blocklisted: {ingress.client_ip}",
                     risk, rid, rule_ids, http_status=403)

    # ── Priority 3: Policy overrides (admin API) ────────────────────────
    if (ip_ov := policy_overrides.get_ip(ingress.client_ip)):
        return _make(ip_ov, f"IP policy override → {ip_ov.value}", risk, rid, rule_ids)

    if (path_ov := policy_overrides.get_path(ingress.path)):
        return _make(path_ov, f"Path override {ingress.path} → {path_ov.value}",
                     risk, rid, rule_ids)

    # ── Priority 4: fail-open mode ──────────────────────────────────────
    if config.fail_open:
        a = Action.LOG_ONLY if risk.score >= thresholds.log_only else Action.ALLOW
        return _make(a, f"fail-open: score={risk.score:.3f}", risk, rid, rule_ids)

    # ── Priority 5: score thresholds ───────────────────────────────────
    s = risk.score

    if s >= thresholds.block:
        return _make(Action.BLOCK,
                     f"Score {s:.3f} ≥ block threshold {thresholds.block}",
                     risk, rid, rule_ids, http_status=403)

    if s >= thresholds.challenge:
        return _make(Action.CHALLENGE,
                     f"Score {s:.3f} ≥ challenge threshold {thresholds.challenge}",
                     risk, rid, rule_ids, http_status=403)

    if s >= thresholds.rate_limit:
        return _make(Action.RATE_LIMIT,
                     f"Score {s:.3f} ≥ rate-limit threshold {thresholds.rate_limit}",
                     risk, rid, rule_ids, http_status=429, retry_after=30)

    if s >= thresholds.log_only:
        return _make(Action.LOG_ONLY,
                     f"Score {s:.3f} ≥ log threshold {thresholds.log_only}",
                     risk, rid, rule_ids)

    return _make(Action.ALLOW, f"Score {s:.3f} below all thresholds",
                 risk, rid, rule_ids)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _make(
    action:      Action,
    reason:      str,
    risk,
    request_id:  str,
    rule_ids:    List[str],
    http_status: int = 200,
    retry_after: int = 0,
) -> WAFDecision:
    d = WAFDecision(
        action              = action,
        reason              = reason,
        risk_score          = risk,
        request_id          = request_id,
        http_status         = http_status if action != Action.ALLOW else 200,
        retry_after_seconds = retry_after,
        rule_ids_fired      = rule_ids,
        categories          = risk.matched_categories,
    )
    level = "warning" if d.is_blocking() else "debug"
    getattr(logger, level)(
        "Decision [%s] %s  score=%.3f  reason=%r  rules=%s",
        request_id[:8], action.value, risk.score, reason, rule_ids[:3],
    )
    return d
