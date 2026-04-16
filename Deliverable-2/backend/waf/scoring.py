"""scoring.py — Unified Risk Scoring Engine"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List
from config import config
from detection import DetectionReport, DetectionResult, ThreatCategory
from logger import get_logger
logger = get_logger("scoring")
cfg = config.scoring; thresholds = config.thresholds

@dataclass
class RiskScore:
    request_id: str; score: float
    rule_contribution: float = 0.0; behavioral_contribution: float = 0.0
    anomaly_contribution: float = 0.0; ml_contribution: float = 0.0
    matched_rule_count: int = 0
    top_findings: List[DetectionResult] = field(default_factory=list)
    matched_categories: List[str] = field(default_factory=list)
    ip_blocklisted: bool = False; obfuscation_detected: bool = False; known_attack_tool: bool = False
    def __post_init__(self): self.score = max(0.0, min(1.0, self.score))
    @property
    def risk_label(self):
        if self.score >= thresholds.block: return "CRITICAL"
        if self.score >= thresholds.challenge: return "HIGH"
        if self.score >= thresholds.rate_limit: return "MEDIUM"
        if self.score >= thresholds.log_only: return "LOW"
        return "CLEAN"

def compute_score(report: DetectionReport, fv, ingress) -> RiskScore:
    rf = [f for f in report.findings if f.engine == "rule_engine"]
    bf = [f for f in report.findings if f.engine == "behavioral_engine"]
    af = [f for f in report.findings if f.engine == "anomaly_engine"]
    mf = [f for f in report.findings if f.engine == "ml_engine"]
    rm = max((f.score for f in rf), default=0.0)
    bm = max((f.score for f in bf), default=0.0)
    am = max((f.score for f in af), default=0.0)
    mm = max((f.score for f in mf), default=0.0)

    w_r = cfg.rule_engine_weight; w_b = cfg.behavioral_engine_weight
    w_a = cfg.anomaly_engine_weight if config.enable_anomaly_engine else 0.0
    w_m = cfg.ml_engine_weight if config.enable_ml_engine else 0.0
    inactive = cfg.anomaly_engine_weight*(1-int(config.enable_anomaly_engine)) + \
               cfg.ml_engine_weight*(1-int(config.enable_ml_engine))
    if inactive > 0:
        base = w_r + w_b
        if base > 0: ratio = inactive/base; w_r *= (1+ratio); w_b *= (1+ratio)
    total = w_r+w_b+w_a+w_m
    if total > 0: w_r/=total; w_b/=total; w_a/=total; w_m/=total

    base_score = w_r*rm + w_b*bm + w_a*am + w_m*mm
    # Confirmed-match floor: a hard rule match >=0.90 guarantees >=0.65
    # (prevents behavioral weight from masking a clear signature hit)
    if any(f.matched and f.score >= 0.90 for f in report.findings):
        base_score = max(base_score, 0.65)
    mult = 1.0
    if ingress.ip_blocklisted: base_score = max(base_score, 1.0)
    known_tool = any(f.rule_id in ("BOT-001","SQLI-010") for f in report.findings)
    if known_tool: base_score = max(base_score, 0.99)
    obf = fv.encoding_depth > 1 or fv.had_null_bytes or fv.had_unicode_tricks or fv.had_base64_payloads
    if obf and rm > 0: mult = min(mult*1.15, 1.5)
    cats = {f.category for f in rf if f.matched}
    if len(cats) >= 3: mult = min(mult*1.20, 1.5)
    mc = sum(1 for f in report.findings if f.matched)
    if mc == 2: mult = min(mult*1.05, 1.5)
    elif mc >= 3: mult = min(mult*1.10, 1.5)
    final = min(1.0, base_score*mult)
    all_f = sorted(report.findings, key=lambda f: f.score, reverse=True)
    return RiskScore(
        request_id=report.request_id, score=final,
        rule_contribution=w_r*rm, behavioral_contribution=w_b*bm,
        anomaly_contribution=w_a*am, ml_contribution=w_m*mm,
        matched_rule_count=mc, top_findings=all_f[:5],
        matched_categories=list({f.category.value for f in all_f if f.matched}),
        ip_blocklisted=ingress.ip_blocklisted, obfuscation_detected=obf, known_attack_tool=known_tool,
    )
