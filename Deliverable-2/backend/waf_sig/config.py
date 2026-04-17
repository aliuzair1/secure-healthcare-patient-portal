"""
config.py — Configuration for the Signature-Based WAF.

Every tuneable value lives here. No detection or decision logic is
hard-coded — change behaviour here without touching the pipeline.

Environment variable overrides are supported for container deployments.
"""

import os
from dataclasses import dataclass, field
from typing import Dict


# ---------------------------------------------------------------------------
# Decision thresholds  (risk score is normalised to [0.0 – 1.0])
# ---------------------------------------------------------------------------

@dataclass
class ThresholdConfig:
    block:      float = 0.75   # score >= this  →  BLOCK  (HTTP 403)
    challenge:  float = 0.50   # score >= this  →  CHALLENGE (CAPTCHA hook)
    rate_limit: float = 0.30   # score >= this  →  RATE-LIMIT (HTTP 429)
    log_only:   float = 0.10   # score >= this  →  allow, but write attack log
    # Below log_only  →  ALLOW silently


# ---------------------------------------------------------------------------
# Scoring tweaks
# ---------------------------------------------------------------------------

@dataclass
class ScoringConfig:
    # Score boost when multiple rules fire in one request (diminishing returns)
    multi_match_boost_2:       float = 1.05   # exactly 2 matches
    multi_match_boost_3:       float = 1.10   # 3 or more matches
    # Extra boost when obfuscation + attack signature co-occur
    obfuscation_boost:         float = 1.15
    # Any single rule with confidence >= this sets a minimum output floor,
    # preventing a high-confidence hit from being diluted by the weighting math
    confirmed_match_threshold: float = 0.90
    confirmed_match_floor:     float = 0.65


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------

@dataclass
class LoggingConfig:
    log_dir:           str  = "logs"
    access_log:        str  = "logs/access.log"
    attack_log:        str  = "logs/attack.log"
    error_log:         str  = "logs/error.log"
    max_bytes:         int  = 10 * 1024 * 1024   # rotate at 10 MB
    backup_count:      int  = 5
    log_request_body:  bool = True               # disable in high-PII environments
    max_body_log_bytes:int  = 4096               # truncate large bodies in logs


# ---------------------------------------------------------------------------
# IP reputation list paths
# ---------------------------------------------------------------------------

@dataclass
class ReputationConfig:
    blocklist_file: str = "rules/ip_blocklist.txt"   # one IP or CIDR per line
    allowlist_file: str = "rules/ip_allowlist.txt"


# ---------------------------------------------------------------------------
# Master config — one object imported everywhere
# ---------------------------------------------------------------------------

@dataclass
class WAFConfig:
    debug:         bool = os.getenv("WAF_DEBUG",    "false").lower() == "true"
    fail_open:     bool = os.getenv("WAF_FAIL_OPEN","false").lower() == "true"
    environment:   str  = os.getenv("WAF_ENV",      "production")
    admin_api_key: str  = os.getenv("WAF_ADMIN_KEY","CHANGE_ME_IN_PRODUCTION")

    thresholds: ThresholdConfig  = field(default_factory=ThresholdConfig)
    scoring:    ScoringConfig    = field(default_factory=ScoringConfig)
    logging:    LoggingConfig    = field(default_factory=LoggingConfig)
    reputation: ReputationConfig = field(default_factory=ReputationConfig)

    # Fine-grained OWASP category toggles (set False to skip a category)
    owasp_toggles: Dict[str, bool] = field(default_factory=lambda: {
        "A01_broken_access_control":     True,
        "A02_cryptographic_failures":    True,
        "A03_injection":                 True,
        "A04_insecure_design":           True,
        "A05_security_misconfiguration": True,
        "A06_vulnerable_components":     True,
        "A07_authentication_failures":   True,
        "A08_data_integrity_failures":   True,
        "A09_logging_failures":          True,
        "A10_ssrf":                      True,
    })


def _load() -> WAFConfig:
    cfg = WAFConfig()
    if v := os.getenv("WAF_BLOCK_THRESHOLD"):     cfg.thresholds.block      = float(v)
    if v := os.getenv("WAF_CHALLENGE_THRESHOLD"): cfg.thresholds.challenge  = float(v)
    if v := os.getenv("WAF_RATE_LIMIT_THRESHOLD"):cfg.thresholds.rate_limit = float(v)
    return cfg


# Singleton — import as:  from config import config
config = _load()
