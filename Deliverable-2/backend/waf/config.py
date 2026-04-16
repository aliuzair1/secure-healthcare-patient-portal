"""
config.py — Centralised configuration for AI-WAF-IDS.

All tuneable values live here. No detection logic is hard-coded.
Environment variables override any field for container-friendly deployment.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ThresholdConfig:
    block:      float = 0.75
    challenge:  float = 0.50
    rate_limit: float = 0.30
    log_only:   float = 0.10


@dataclass
class RateLimitConfig:
    window_seconds:   int   = 60
    max_requests:     int   = 300
    max_suspicious:   int   = 50
    burst_multiplier: float = 2.0


@dataclass
class BehavioralConfig:
    session_ttl_seconds:            int   = 1800
    max_failed_auth:                int   = 5
    failed_auth_window:             int   = 300
    max_404_per_window:             int   = 20
    max_param_mutation_rate:        float = 0.80
    credential_stuffing_threshold:  int   = 10
    api_abuse_rps:                  float = 50.0
    user_agent_anomaly_weight:      float = 0.3


@dataclass
class ScoringConfig:
    rule_engine_weight:      float = 0.55
    behavioral_engine_weight:float = 0.30
    anomaly_engine_weight:   float = 0.00
    ml_engine_weight:        float = 0.00


@dataclass
class LoggingConfig:
    log_dir:           str = "logs"
    access_log:        str = "logs/access.log"
    attack_log:        str = "logs/attack.log"
    error_log:         str = "logs/error.log"
    max_bytes:         int = 10 * 1024 * 1024
    backup_count:      int = 5
    log_request_body:  bool = True
    max_body_log_bytes:int = 4096


@dataclass
class MLConfig:
    enabled:             bool  = False
    model_path:          str   = ""
    model_type:          str   = ""          # "sklearn"|"onnx"|"rest"
    inference_timeout_ms:int   = 5
    grpc_endpoint:       str   = ""
    rest_endpoint:       str   = ""
    feature_version:     int   = 1


@dataclass
class AnomalyConfig:
    enabled:               bool  = False
    algorithm:             str   = "lof"
    contamination:         float = 0.05
    baseline_path:         str   = ""
    retrain_interval_hours:int   = 24


@dataclass
class ReputationConfig:
    enable_geoip:      bool      = False
    blocked_countries: List[str] = field(default_factory=list)
    blocklist_file:    str       = "rules/ip_blocklist.txt"
    allowlist_file:    str       = "rules/ip_allowlist.txt"
    tor_exit_check:    bool      = False


@dataclass
class WAFConfig:
    debug:                    bool = os.getenv("WAF_DEBUG","false").lower() == "true"
    fail_open:                bool = False
    environment:              str  = os.getenv("WAF_ENV","production")
    admin_api_key:            str  = os.getenv("WAF_ADMIN_KEY","CHANGE_ME_IN_PRODUCTION")

    enable_rule_engine:       bool = True
    enable_behavioral_engine: bool = True
    enable_anomaly_engine:    bool = False
    enable_ml_engine:         bool = False

    thresholds:  ThresholdConfig  = field(default_factory=ThresholdConfig)
    rate_limit:  RateLimitConfig  = field(default_factory=RateLimitConfig)
    behavioral:  BehavioralConfig = field(default_factory=BehavioralConfig)
    scoring:     ScoringConfig    = field(default_factory=ScoringConfig)
    logging:     LoggingConfig    = field(default_factory=LoggingConfig)
    ml:          MLConfig         = field(default_factory=MLConfig)
    anomaly:     AnomalyConfig    = field(default_factory=AnomalyConfig)
    reputation:  ReputationConfig = field(default_factory=ReputationConfig)

    owasp_toggles: Dict[str,bool] = field(default_factory=lambda: {
        "A01_broken_access_control":   True,
        "A02_cryptographic_failures":  True,
        "A03_injection":               True,
        "A04_insecure_design":         True,
        "A05_security_misconfiguration":True,
        "A06_vulnerable_components":   True,
        "A07_authentication_failures": True,
        "A08_data_integrity_failures": True,
        "A09_logging_failures":        True,
        "A10_ssrf":                    True,
    })


def _load() -> WAFConfig:
    cfg = WAFConfig()
    if v := os.getenv("WAF_FAIL_OPEN"):  cfg.fail_open = v.lower() == "true"
    if v := os.getenv("WAF_BLOCK_THRESHOLD"):  cfg.thresholds.block = float(v)
    if v := os.getenv("WAF_ML_ENABLED"):  cfg.ml.enabled = v.lower() == "true"
    if v := os.getenv("WAF_ML_MODEL_PATH"):  cfg.ml.model_path = v
    if v := os.getenv("WAF_ML_MODEL_TYPE"):  cfg.ml.model_type = v
    if v := os.getenv("WAF_ML_REST_ENDPOINT"):  cfg.ml.rest_endpoint = v
    return cfg


# Module-level singleton — import as: from config import config
config = _load()
