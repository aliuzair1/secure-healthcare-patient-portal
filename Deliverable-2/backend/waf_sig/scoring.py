"""
scoring.py — Risk Scoring Engine (Pipeline Step 4)

Takes the DetectionReport (all rule findings) and produces a single
normalised RiskScore in [0.0 – 1.0].

Algorithm
---------
  1. Base score  = max rule score from all findings.
  2. Multi-match boost: if 2 or 3+ distinct rules fire, apply a small
     multiplier (diminishing returns — the first match is the most
     informative).
  3. Obfuscation boost: if the normaliser detected encoding tricks AND
     at least one rule fired, apply an additional multiplier.
  4. Confirmed-match floor: if any single rule has confidence ≥ 0.90,
     the final score is raised to at least 0.65. This prevents a high-
     confidence signature hit from being diluted to below the BLOCK
     threshold by the multiplier arithmetic.
  5. Clamp to [0.0, 1.0].

The RiskScore also carries metadata consumed by the Decision Engine
and Logger: matched categories, top findings, and escalation flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from config import config
from detection import DetectionReport, DetectionResult, ThreatCategory
from logger import get_logger

logger = get_logger("scoring")

thresholds = config.thresholds
scoring    = config.scoring


# ---------------------------------------------------------------------------
# RiskScore  —  output of this module
# ---------------------------------------------------------------------------

@dataclass
class RiskScore:
    request_id:           str
    score:                float         # unified [0.0 – 1.0]

    matched_rule_count:   int           = 0
    top_findings:         List[DetectionResult] = field(default_factory=list)
    matched_categories:   List[str]     = field(default_factory=list)

    # Escalation flags (used by logger for audit trail)
    ip_blocklisted:       bool          = False
    obfuscation_detected: bool          = False
    known_attack_tool:    bool          = False

    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))

    @property
    def risk_label(self) -> str:
        if self.score >= thresholds.block:      return "CRITICAL"
        if self.score >= thresholds.challenge:  return "HIGH"
        if self.score >= thresholds.rate_limit: return "MEDIUM"
        if self.score >= thresholds.log_only:   return "LOW"
        return "CLEAN"


# ---------------------------------------------------------------------------
# Public scoring function
# ---------------------------------------------------------------------------

def compute_score(
    report:  DetectionReport,
    nr,                        # NormalisedRequest
    ingress,                   # IngressRequest
) -> RiskScore:
    """Compute a unified RiskScore from a DetectionReport."""

    findings = report.findings

    # ── 1. Base score ──────────────────────────────────────────────────────
    base = max((f.score for f in findings), default=0.0)

    # ── 2. Multi-match boost (diminishing returns) ─────────────────────────
    match_count = sum(1 for f in findings if f.matched)
    multiplier  = 1.0
    if match_count == 2:
        multiplier = scoring.multi_match_boost_2
    elif match_count >= 3:
        multiplier = scoring.multi_match_boost_3

    # ── 3. Obfuscation boost (only when an attack rule also fired) ─────────
    obfuscation = (
        nr.encoding_depth > 1
        or nr.had_null_bytes
        or nr.had_unicode_tricks
        or nr.had_base64_payloads
    )
    if obfuscation and base > 0:
        multiplier = min(multiplier * scoring.obfuscation_boost, 2.0)

    raw = base * multiplier

    # ── 4. Confirmed-match floor ───────────────────────────────────────────
    if any(f.matched and f.score >= scoring.confirmed_match_threshold for f in findings):
        raw = max(raw, scoring.confirmed_match_floor)

    # ── 5. IP blocklist override ───────────────────────────────────────────
    if ingress.ip_blocklisted:
        raw = 1.0

    # Known attack tool (BOT-001 / SQLI-010) — hard ceiling at 1.0
    known_tool = any(f.rule_id in ("BOT-001", "SQLI-010") for f in findings)
    if known_tool:
        raw = max(raw, 0.99)

    final = max(0.0, min(1.0, raw))

    # ── Build result ───────────────────────────────────────────────────────
    sorted_findings = sorted(findings, key=lambda f: f.score, reverse=True)
    categories      = list({f.category.value for f in sorted_findings if f.matched})

    risk = RiskScore(
        request_id          = report.request_id,
        score               = final,
        matched_rule_count  = match_count,
        top_findings        = sorted_findings[:5],
        matched_categories  = categories,
        ip_blocklisted      = ingress.ip_blocklisted,
        obfuscation_detected= obfuscation,
        known_attack_tool   = known_tool,
    )

    logger.debug(
        "Score for %s: %.3f (%s) — rules=%d obf=%s tool=%s",
        ingress.request_id[:8], final, risk.risk_label,
        match_count, obfuscation, known_tool,
    )
    return risk
