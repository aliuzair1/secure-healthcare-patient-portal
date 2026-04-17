"""
detection/__init__.py — Detection Engine Base Classes

Defines:
  ThreatCategory  — OWASP Top 10 + supplementary categories
  DetectionResult — a single finding from any detector
  DetectionReport — all findings for one request
  BaseDetector    — interface every detector implements
  DetectorRegistry— registers and runs all active detectors

Adding a new detector:
  1. Subclass BaseDetector in a new file inside detection/
  2. Call registry.register(MyDetector()) in waf_engine.py
  No other file changes needed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Threat categories
# ---------------------------------------------------------------------------

class ThreatCategory(str, Enum):
    # OWASP Top 10 2021
    A01_BROKEN_ACCESS_CONTROL = "A01:BrokenAccessControl"
    A02_CRYPTOGRAPHIC_FAILURE = "A02:CryptographicFailure"
    A03_INJECTION             = "A03:Injection"
    A03_SQLI                  = "A03:SQLInjection"
    A03_XSS                   = "A03:XSS"
    A03_CMDI                  = "A03:CommandInjection"
    A03_XXE                   = "A03:XXE"
    A03_SSTI                  = "A03:SSTI"
    A03_LDAPI                 = "A03:LDAPInjection"
    A04_INSECURE_DESIGN       = "A04:InsecureDesign"
    A05_MISCONFIGURATION      = "A05:SecurityMisconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:VulnerableComponents"
    A07_AUTH_FAILURE          = "A07:AuthenticationFailure"
    A08_DATA_INTEGRITY        = "A08:DataIntegrityFailure"
    A09_LOGGING_FAILURE       = "A09:LoggingMonitoringFailure"
    A10_SSRF                  = "A10:SSRF"
    # Supplementary
    PATH_TRAVERSAL            = "PathTraversal"
    HTTP_SMUGGLING            = "HTTPSmuggling"
    OPEN_REDIRECT             = "OpenRedirect"
    BOT_TRAFFIC               = "BotTraffic"
    API_ABUSE                 = "APIAbuse"
    PAYLOAD_OBFUSCATION       = "PayloadObfuscation"
    UNKNOWN                   = "Unknown"


# ---------------------------------------------------------------------------
# DetectionResult — one finding
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    score:    float           # [0.0 – 1.0] confidence this is a real attack
    matched:  bool            # True = hard signature match; False = heuristic signal
    category: ThreatCategory
    rule_id:  str             # e.g. "SQLI-001"
    details:  str             # human-readable description
    evidence: Dict[str, Any] = field(default_factory=dict)
    engine:   str = ""        # set by DetectorRegistry.run_all()

    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))


# ---------------------------------------------------------------------------
# DetectionReport — aggregated results for one request
# ---------------------------------------------------------------------------

@dataclass
class DetectionReport:
    request_id:    str
    findings:      List[DetectionResult] = field(default_factory=list)
    engine_errors: Dict[str, str]        = field(default_factory=dict)

    def add(self, result: DetectionResult) -> None:
        self.findings.append(result)

    @property
    def max_score(self) -> float:
        return max((f.score for f in self.findings), default=0.0)

    @property
    def matched_categories(self) -> List[ThreatCategory]:
        return [f.category for f in self.findings if f.matched]


# ---------------------------------------------------------------------------
# BaseDetector — interface for all detection engines
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """
    All detection engines implement this interface.

    detect() must NEVER raise — catch all errors internally and return
    an empty list on failure. The pipeline logs engine errors separately.
    """
    name:    str  = "base"
    enabled: bool = True

    @abstractmethod
    def detect(self, nr, report: DetectionReport) -> List[DetectionResult]:
        ...

    def is_available(self) -> bool:
        return self.enabled


# ---------------------------------------------------------------------------
# DetectorRegistry  —  Strategy + Registry pattern
# ---------------------------------------------------------------------------

class DetectorRegistry:
    """
    Holds all registered detectors and runs them in registration order.

    Usage:
        registry = DetectorRegistry()
        registry.register(RuleEngine())
        registry.run_all(nr, report)
    """

    def __init__(self):
        self._detectors: List[BaseDetector] = []

    def register(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)

    def unregister(self, name: str) -> None:
        self._detectors = [d for d in self._detectors if d.name != name]

    def run_all(self, nr, report: DetectionReport) -> DetectionReport:
        for detector in self._detectors:
            if not detector.is_available():
                continue
            try:
                for finding in detector.detect(nr, report):
                    finding.engine = detector.name
                    report.add(finding)
            except Exception as exc:
                report.engine_errors[detector.name] = str(exc)
        return report
