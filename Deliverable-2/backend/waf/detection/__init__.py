"""detection/__init__.py — Detection Engine Base Classes & Registry"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class ThreatCategory(str, Enum):
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
    PATH_TRAVERSAL            = "PathTraversal"
    HTTP_SMUGGLING            = "HTTPSmuggling"
    OPEN_REDIRECT             = "OpenRedirect"
    BOT_TRAFFIC               = "BotTraffic"
    API_ABUSE                 = "APIAbuse"
    CREDENTIAL_STUFFING       = "CredentialStuffing"
    ZERO_DAY_ANOMALY          = "ZeroDayAnomaly"
    PAYLOAD_OBFUSCATION       = "PayloadObfuscation"
    RATE_ABUSE                = "RateAbuse"
    IP_REPUTATION             = "IPReputation"
    UNKNOWN                   = "Unknown"

@dataclass
class DetectionResult:
    score: float
    matched: bool
    category: ThreatCategory
    rule_id: str
    details: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    engine: str = ""
    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))

@dataclass
class DetectionReport:
    request_id: str
    findings: List[DetectionResult] = field(default_factory=list)
    rule_engine_score: float = 0.0
    behavioral_score: float = 0.0
    anomaly_score: float = 0.0
    ml_score: float = 0.0
    engine_errors: Dict[str, str] = field(default_factory=dict)
    def add(self, r): self.findings.append(r)
    @property
    def max_score(self): return max((f.score for f in self.findings), default=0.0)
    @property
    def matched_categories(self): return [f.category for f in self.findings if f.matched]

class BaseDetector(ABC):
    name: str = "base"
    enabled: bool = True
    @abstractmethod
    def detect(self, nr, fv) -> List[DetectionResult]: ...
    def is_available(self): return self.enabled

class DetectorRegistry:
    def __init__(self): self._detectors: List[BaseDetector] = []
    def register(self, d): self._detectors.append(d)
    def unregister(self, name): self._detectors = [d for d in self._detectors if d.name != name]
    def get(self, name): return next((d for d in self._detectors if d.name == name), None)
    def run_all(self, nr, fv, report):
        for det in self._detectors:
            if not det.is_available(): continue
            try:
                for f in det.detect(nr, fv):
                    f.engine = det.name; report.add(f)
            except Exception as exc:
                report.engine_errors[det.name] = str(exc)
        return report
