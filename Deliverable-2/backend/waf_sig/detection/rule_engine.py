"""
detection/rule_engine.py — Signature-Based WAF Rule Engine

Covers every OWASP Top 10 2021 category plus common supplementary threats.

Rule structure
--------------
  rule_id     Unique identifier  (e.g. "SQLI-001")
  description Human-readable summary
  category    ThreatCategory enum value
  pattern     Raw regex string — compiled once at class init
  score       Confidence [0.0 – 1.0] when matched
  apply_to    Which request fields to scan (default: ["all_inputs"])
  enabled     Can be flipped False at runtime without removing the rule

Adding a rule
-------------
  Append a WAFRule() to RULES. That is the only change required.
  No pipeline code needs to be touched.

Disabling a rule at runtime
----------------------------
  from detection.rule_engine import RULES
  next(r for r in RULES if r.rule_id == "SQLI-003").enabled = False
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

from detection import BaseDetector, DetectionReport, DetectionResult, ThreatCategory
from logger import get_logger

logger = get_logger("rule_engine")


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass
class WAFRule:
    rule_id:        str
    description:    str
    category:       ThreatCategory
    pattern:        str
    score:          float
    apply_to:       List[str] = field(default_factory=lambda: ["all_inputs"])
    case_sensitive: bool = False
    enabled:        bool = True
    _compiled:      Optional[Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self._compiled = re.compile(self.pattern, flags | re.DOTALL)

    def match(self, text: str) -> Optional[re.Match]:
        if not self.enabled or not text:
            return None
        return self._compiled.search(text)


# ---------------------------------------------------------------------------
# Rule catalogue  —  grouped by OWASP category
# ---------------------------------------------------------------------------

RULES: List[WAFRule] = [

    # ═══════════════════════════════════════════════════════════════════════
    # A03 — SQL Injection
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="SQLI-001", score=0.95,
        description="UNION-based SQL injection",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\bunion\b.{0,30}\bselect\b",
    ),
    WAFRule(
        rule_id="SQLI-002", score=0.90,
        description="SQL comment bypass with DML keyword",
        category=ThreatCategory.A03_SQLI,
        pattern=r"(--|#|/\*).{0,20}(select|insert|update|delete|drop|create|alter|exec)\b",
    ),
    WAFRule(
        rule_id="SQLI-003", score=0.75,
        description="Boolean-based blind injection (1=1, 'a'='a')",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\b1\s*=\s*1\b|\b0\s*=\s*0\b|'\w+'\s*=\s*'\w+'",
    ),
    WAFRule(
        rule_id="SQLI-004", score=0.95,
        description="Time-based blind injection (SLEEP / WAITFOR / BENCHMARK)",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\b(sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep\s*\()",
    ),
    WAFRule(
        rule_id="SQLI-005", score=0.90,
        description="Stacked queries / batch execution",
        category=ThreatCategory.A03_SQLI,
        pattern=r";\s*(select|insert|update|delete|drop|create|alter|exec|execute)\b",
    ),
    WAFRule(
        rule_id="SQLI-006", score=0.90,
        description="Error-based injection (extractvalue / updatexml)",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\b(extractvalue|updatexml|exp\s*\(|floor\s*\(.*rand\s*\()\b",
    ),
    WAFRule(
        rule_id="SQLI-007", score=0.95,
        description="Out-of-band: LOAD_FILE / INTO OUTFILE / DUMPFILE",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\b(load_file\s*\(|into\s+outfile|into\s+dumpfile)\b",
    ),
    WAFRule(
        rule_id="SQLI-008", score=0.85,
        description="Meta-table access (information_schema, sysobjects, pg_shadow)",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\b(information_schema|sysobjects|syscolumns|sysusers|mysql\.user|pg_shadow)\b",
    ),
    WAFRule(
        rule_id="SQLI-009", score=0.80,
        description="HAVING / GROUP BY clause injection",
        category=ThreatCategory.A03_SQLI,
        pattern=r"\bhaving\s+\d+\s*=\s*\d+|\bgroup\s+by\s+\d+\b",
    ),
    WAFRule(
        rule_id="SQLI-010", score=0.99,
        description="sqlmap tool signature in any field",
        category=ThreatCategory.A03_SQLI,
        pattern=r"sqlmap",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A03 — Cross-Site Scripting
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="XSS-001", score=0.95,
        description="<script> tag injection",
        category=ThreatCategory.A03_XSS,
        pattern=r"<\s*/?\s*script[\s>]",
    ),
    WAFRule(
        rule_id="XSS-002", score=0.90,
        description="javascript: URI scheme",
        category=ThreatCategory.A03_XSS,
        pattern=r"javascript\s*:",
    ),
    WAFRule(
        rule_id="XSS-003", score=0.85,
        description="Inline event handler  (on*=…)",
        category=ThreatCategory.A03_XSS,
        pattern=r"\bon\w{1,20}\s*=",
    ),
    WAFRule(
        rule_id="XSS-004", score=0.80,
        description="eval() / document.write() / innerHTML sink",
        category=ThreatCategory.A03_XSS,
        pattern=r"\b(eval|document\.write|innerHTML|outerHTML|document\.cookie)\s*[\(\=]",
    ),
    WAFRule(
        rule_id="XSS-005", score=0.85,
        description="data:text/html URI injection",
        category=ThreatCategory.A03_XSS,
        pattern=r"data\s*:\s*text/html",
    ),
    WAFRule(
        rule_id="XSS-006", score=0.90,
        description="SVG-based script injection",
        category=ThreatCategory.A03_XSS,
        pattern=r"<\s*svg[\s>].*?(script|onload|onerror)",
    ),
    WAFRule(
        rule_id="XSS-007", score=0.85,
        description="CSS expression() injection (IE)",
        category=ThreatCategory.A03_XSS,
        pattern=r"expression\s*\(",
    ),
    WAFRule(
        rule_id="XSS-008", score=0.70,
        description="Framework template injection  ({{…}} / [[…]])",
        category=ThreatCategory.A03_XSS,
        # Restrict to body/query — JWT Bearer tokens in Authorization headers
        # contain base64 characters that can accidentally match this pattern.
        apply_to=["body", "query", "cookies"],
        pattern=r"\{\{.*?\}\}|\[\[.*?\]\]",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A03 — Command Injection
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="CMDI-001", score=0.90,
        description="Unix shell metachar + common command",
        category=ThreatCategory.A03_CMDI,
        pattern=(
            r"[;&|`]\s*"
            r"(ls|cat|pwd|id|whoami|uname|ifconfig|netstat|ps|wget|curl|"
            r"chmod|chown|rm|mv|cp|echo|bash|sh|python|perl|ruby|php)\b"
        ),
    ),
    WAFRule(
        rule_id="CMDI-002", score=0.85,
        description="Command substitution: $() or backtick",
        category=ThreatCategory.A03_CMDI,
        pattern=r"\$\([^)]+\)|`[^`]+`",
    ),
    WAFRule(
        rule_id="CMDI-003", score=0.90,
        description="Windows: cmd.exe / PowerShell patterns",
        category=ThreatCategory.A03_CMDI,
        pattern=r"(cmd\.exe|powershell|invoke-expression|iex\s*\(|certutil|bitsadmin|mshta|wscript|cscript)",
    ),
    WAFRule(
        rule_id="CMDI-004", score=0.85,
        description="Unix sensitive file access (/etc/passwd, /etc/shadow …)",
        category=ThreatCategory.A03_CMDI,
        pattern=r"/etc/(passwd|shadow|group|hosts|crontab|sudoers)",
    ),
    WAFRule(
        rule_id="CMDI-005", score=0.85,
        description="Windows system file access (system32, win.ini …)",
        category=ThreatCategory.A03_CMDI,
        pattern=r"(windows[\\/]system32|win\.ini|autoexec\.bat|boot\.ini|ntds\.dit)",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # Path Traversal / LFI / RFI
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="PT-001", score=0.90,
        description="../ directory traversal sequence",
        category=ThreatCategory.PATH_TRAVERSAL,
        pattern=r"(\.\.[/\\]){2,}|(\.\.[/\\]).*(passwd|shadow|win\.ini|web\.config)",
    ),
    WAFRule(
        rule_id="PT-002", score=0.95,
        description="Null-byte extension bypass  (.php%00.jpg)",
        category=ThreatCategory.PATH_TRAVERSAL,
        pattern=r"\.php(\x00|%00|%2500)\.",
    ),
    WAFRule(
        rule_id="PT-003", score=0.90,
        description="Remote file inclusion: http(s):// in file parameter",
        category=ThreatCategory.PATH_TRAVERSAL,
        pattern=r"(include|require|file|path|page|doc|src)\s*=\s*https?://",
    ),
    WAFRule(
        rule_id="PT-004", score=0.95,
        description="/proc/self/ access (Linux container escape)",
        category=ThreatCategory.PATH_TRAVERSAL,
        pattern=r"/proc/self/(environ|cmdline|maps|fd)",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A10 — SSRF
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="SSRF-001", score=0.95,
        description="SSRF: request to internal / loopback address",
        category=ThreatCategory.A10_SSRF,
        pattern=(
            r"https?://"
            r"(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|::1"
            r"|169\.254\.\d+\.\d+"
            r"|10\.\d+\.\d+\.\d+"
            r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
            r"|192\.168\.\d+\.\d+)"
        ),
    ),
    WAFRule(
        rule_id="SSRF-002", score=0.99,
        description="SSRF: cloud metadata endpoint (AWS / GCP / Azure)",
        category=ThreatCategory.A10_SSRF,
        pattern=r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|metadata\.azure\.internal",
    ),
    WAFRule(
        rule_id="SSRF-003", score=0.90,
        description="SSRF: file:// URI scheme",
        category=ThreatCategory.A10_SSRF,
        pattern=r"file://",
    ),
    WAFRule(
        rule_id="SSRF-004", score=0.85,
        description="SSRF: dict:// gopher:// ftp:// scheme abuse",
        category=ThreatCategory.A10_SSRF,
        pattern=r"(dict|gopher|ftp)://",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A03 — XXE
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="XXE-001", score=0.95,
        description="XXE: DOCTYPE with ENTITY declaration",
        category=ThreatCategory.A03_XXE,
        pattern=r"<!DOCTYPE\s+\w+\s*\[.*<!ENTITY",
    ),
    WAFRule(
        rule_id="XXE-002", score=0.95,
        description="XXE: SYSTEM entity reference",
        category=ThreatCategory.A03_XXE,
        pattern=r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']",
    ),
    WAFRule(
        rule_id="XXE-003", score=0.90,
        description="XXE: PUBLIC entity reference",
        category=ThreatCategory.A03_XXE,
        pattern=r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"']",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A03 — Server-Side Template Injection
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="SSTI-001", score=0.90,
        description="SSTI: Jinja2/Twig dangerous object access",
        category=ThreatCategory.A03_SSTI,
        pattern=r"\{\{.{0,30}(config|self|request|__class__|__mro__|__import__|os\.system|popen).{0,30}\}\}",
    ),
    WAFRule(
        rule_id="SSTI-002", score=0.80,
        description="SSTI: arithmetic probe  {{7*7}}",
        category=ThreatCategory.A03_SSTI,
        pattern=r"\{\{\s*\d+\s*[\*\+\-]\s*\d+\s*\}\}",
    ),
    WAFRule(
        rule_id="SSTI-003", score=0.90,
        description="SSTI: Ruby/ERB code execution",
        category=ThreatCategory.A03_SSTI,
        pattern=r"<%=.{0,30}(system|exec|`|IO\.popen).{0,30}%>",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A03 — LDAP Injection
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="LDAPI-001", score=0.85,
        description="LDAP filter metacharacters",
        category=ThreatCategory.A03_LDAPI,
        pattern=r"[)(|*\\]\s*(cn|uid|ou|dc|sn|mail|objectclass)\s*=",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # HTTP Response Splitting / Smuggling
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="CRLF-001", score=0.85,
        description="CRLF injection / HTTP response splitting",
        category=ThreatCategory.HTTP_SMUGGLING,
        # Restrict to body/query only — headers are naturally newline-separated when
        # concatenated, which causes false positives on every legitimate request.
        apply_to=["body", "query"],
        pattern=r"%0[dD]%0[aA]|%0[aA]%0[dD]",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # Open Redirect
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="REDIR-001", score=0.75,
        description="Open redirect: external URL in redirect parameter",
        category=ThreatCategory.OPEN_REDIRECT,
        pattern=r"(redirect|return|next|url|goto|target|redir|dest)\s*=\s*https?://(?!localhost)",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A01 — Broken Access Control
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="BAC-001", score=0.70,
        description="Forced browsing: suspicious admin / config endpoint",
        category=ThreatCategory.A01_BROKEN_ACCESS_CONTROL,
        apply_to=["path"],
        # /api/admin is a legitimate route in this application; only flag external
        # admin panel probing tools (phpmyadmin, wp-admin) and sensitive files.
        pattern=r"/(administrator|phpmyadmin|wp-admin|setup|install|backup|\.env|\.htaccess|web\.config)",
    ),
    WAFRule(
        rule_id="BAC-002", score=0.90,
        description="SQL in authentication username / password field",
        category=ThreatCategory.A07_AUTH_FAILURE,
        pattern=r"(username|user|email|login|pass|password)\s*=.*('|\"|--|#|/\*|union|select|or\s+1)",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A02 — Cryptographic Failures / Sensitive Data Exposure
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="CRYPTO-001", score=0.70,
        description="Secret / token / password transmitted in URL query string",
        category=ThreatCategory.A02_CRYPTOGRAPHIC_FAILURE,
        apply_to=["path", "query"],
        pattern=r"[?&](password|passwd|pwd|token|api_key|apikey|secret|private_key|access_token)=",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # A05 — Security Misconfiguration
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="MISCONFIG-001", score=0.65,
        description="Debug / diagnostic / framework endpoint probing",
        category=ThreatCategory.A05_MISCONFIGURATION,
        apply_to=["path"],
        pattern=r"/(phpinfo|server-status|server-info|actuator/|metrics|swagger-ui|api-docs|openapi\.json)",
    ),
    WAFRule(
        rule_id="MISCONFIG-002", score=0.65,
        description="Backup / configuration file access",
        category=ThreatCategory.A05_MISCONFIGURATION,
        apply_to=["path"],
        pattern=r"\.(bak|old|orig|backup|swp|sql|db|sqlite|cfg|ini|env|pem|key|crt|pfx)\b",
    ),
    WAFRule(
        rule_id="MISCONFIG-003", score=0.75,
        description="Version control / CI metadata access (.git, .svn …)",
        category=ThreatCategory.A05_MISCONFIGURATION,
        apply_to=["path"],
        pattern=r"/(\.git|\.svn|\.hg|\.DS_Store|Dockerfile|docker-compose\.yml)",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # Payload Obfuscation  (cross-category escalation)
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="OBF-001", score=0.70,
        description="Double URL-encoding (%25xx)",
        category=ThreatCategory.PAYLOAD_OBFUSCATION,
        pattern=r"%25[0-9a-fA-F]{2}",
    ),
    WAFRule(
        rule_id="OBF-002", score=0.75,
        description="Null-byte injection (%00)",
        category=ThreatCategory.PAYLOAD_OBFUSCATION,
        pattern=r"%00|\\x00|\x00",
    ),
    WAFRule(
        rule_id="OBF-003", score=0.65,
        description="Unicode full-width character evasion",
        category=ThreatCategory.PAYLOAD_OBFUSCATION,
        pattern=r"[\uff01-\uff5e]",
    ),

    # ═══════════════════════════════════════════════════════════════════════
    # Bot / Scanner Fingerprinting
    # ═══════════════════════════════════════════════════════════════════════
    WAFRule(
        rule_id="BOT-001", score=0.99,
        description="Known attack tool User-Agent",
        category=ThreatCategory.BOT_TRAFFIC,
        apply_to=["user_agent"],
        pattern=(
            r"(sqlmap|nikto|nmap|masscan|zgrab|w3af|burpsuite|dirbuster|"
            r"gobuster|wfuzz|hydra|medusa|acunetix|netsparker|openvas|havij|"
            r"skipfish|appscan|webinspect|nessus|vega|paros|owasp.zap)"
        ),
    ),
    WAFRule(
        rule_id="BOT-002", score=0.50,
        description="Empty User-Agent (automated / headless client)",
        category=ThreatCategory.BOT_TRAFFIC,
        apply_to=["user_agent"],
        pattern=r"^$",
    ),
]


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine(BaseDetector):
    """
    Applies all enabled WAFRules to the normalised request.
    Returns one DetectionResult per matched rule.
    """
    name = "rule_engine"

    def __init__(self, rules: Optional[List[WAFRule]] = None):
        self._rules = rules or RULES
        logger.info("RuleEngine: %d rules loaded", len(self._rules))

    def detect(self, nr, report: DetectionReport) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        ingress = nr.ingress

        # Build the field map for targeted rules
        field_map = {
            "all_inputs": nr.all_inputs,
            "path":       nr.decoded_path,
            "query":      nr.decoded_query_string,
            "headers":    " ".join(f"{k}: {v}" for k, v in nr.decoded_headers.items()),
            "body":       nr.body_raw_decoded,
            "user_agent": ingress.user_agent,
            "cookies":    " ".join(f"{k}={v}" for k, v in nr.decoded_cookies.items()),
        }

        for rule in self._rules:
            if not rule.enabled:
                continue
            targets = rule.apply_to if rule.apply_to != ["all_inputs"] else ["all_inputs"]
            for target in targets:
                m = rule.match(field_map.get(target, ""))
                if m:
                    snippet = m.group(0)[:200]
                    result = DetectionResult(
                        score    = rule.score,
                        matched  = True,
                        category = rule.category,
                        rule_id  = rule.rule_id,
                        details  = f"{rule.description} [field: {target}]",
                        evidence = {
                            "matched_text": snippet,
                            "field":        target,
                            "rule_id":      rule.rule_id,
                        },
                    )
                    # Obfuscation escalation: bump score if payload was encoded
                    if nr.encoding_depth > 1 or nr.had_null_bytes or nr.had_unicode_tricks:
                        result.score = min(1.0, result.score + 0.10)
                    results.append(result)
                    break   # one finding per rule per request is sufficient

        if results:
            logger.info(
                "RuleEngine: %d findings for %s (max=%.2f)",
                len(results), ingress.request_id[:8],
                max(r.score for r in results),
            )
        return results


# Needed for the Optional type hint inside __init__
from typing import Optional
