"""detection/rule_engine.py — Signature-Based WAF Rule Engine"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern
from detection import BaseDetector, DetectionResult, ThreatCategory
from logger import get_logger
logger = get_logger("rule_engine")

@dataclass
class WAFRule:
    rule_id: str; description: str; category: ThreatCategory
    pattern: str; score: float
    apply_to: List[str] = field(default_factory=lambda: ["all_inputs"])
    case_sensitive: bool = False
    compiled: Optional[Pattern] = field(default=None, init=False, repr=False)
    def __post_init__(self):
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self.compiled = re.compile(self.pattern, flags | re.DOTALL)

RULES: List[WAFRule] = [
    # SQL Injection
    WAFRule("SQLI-001","UNION SELECT injection",ThreatCategory.A03_SQLI,r"\bunion\b.{0,20}\bselect\b",0.95),
    WAFRule("SQLI-002","SQL comment with keyword",ThreatCategory.A03_SQLI,r"(--|#|/\*).*(select|insert|update|delete|drop|create|alter|exec)",0.90),
    WAFRule("SQLI-003","Boolean-based blind (1=1)",ThreatCategory.A03_SQLI,r"(\b|\')(\d+)\s*=\s*\2\b|'[a-z]'\s*=\s*'[a-z]'|1\s*=\s*1|0\s*=\s*0",0.75),
    WAFRule("SQLI-004","Time-based blind SLEEP/WAITFOR",ThreatCategory.A03_SQLI,r"\b(sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep\s*\()",0.95),
    WAFRule("SQLI-005","Stacked queries",ThreatCategory.A03_SQLI,r";\s*(select|insert|update|delete|drop|exec|execute)\b",0.90),
    WAFRule("SQLI-006","Error-based extractvalue/updatexml",ThreatCategory.A03_SQLI,r"\b(extractvalue|updatexml|exp\s*\(|floor\s*\(.*rand\s*\()\b",0.90),
    WAFRule("SQLI-007","LOAD_FILE / INTO OUTFILE",ThreatCategory.A03_SQLI,r"\b(load_file\s*\(|into\s+outfile|into\s+dumpfile)\b",0.95),
    WAFRule("SQLI-008","information_schema / sysobjects",ThreatCategory.A03_SQLI,r"\b(information_schema|sysobjects|syscolumns|sysusers|mysql\.user|pg_shadow)\b",0.85),
    WAFRule("SQLI-009","HAVING / GROUP BY injection",ThreatCategory.A03_SQLI,r"\bhaving\s+\d+\s*=\s*\d+|\bgroup\s+by\s+\d+\b",0.80),
    WAFRule("SQLI-010","sqlmap tool signature",ThreatCategory.A03_SQLI,r"sqlmap|sqlmap\.py",0.99,apply_to=["user_agent","all_inputs"]),
    # XSS
    WAFRule("XSS-001","<script> tag injection",ThreatCategory.A03_XSS,r"<\s*/?\s*script[\s>]",0.95),
    WAFRule("XSS-002","javascript: URI",ThreatCategory.A03_XSS,r"javascript\s*:",0.90),
    WAFRule("XSS-003","Inline event handler on*=",ThreatCategory.A03_XSS,r"\bon\w{1,20}\s*=",0.85),
    WAFRule("XSS-004","eval/document.write/innerHTML",ThreatCategory.A03_XSS,r"\b(eval|document\.write|innerHTML|outerHTML|document\.cookie)\s*[\(\=]",0.80),
    WAFRule("XSS-005","data: URI HTML",ThreatCategory.A03_XSS,r"data\s*:\s*text/html",0.85),
    WAFRule("XSS-006","SVG script injection",ThreatCategory.A03_XSS,r"<\s*svg[\s>].*?(script|onload|onerror)",0.90),
    WAFRule("XSS-007","CSS expression()",ThreatCategory.A03_XSS,r"expression\s*\(",0.85),
    WAFRule("XSS-008","Template injection {{}}",ThreatCategory.A03_XSS,r"\{\{.*?\}\}|\[\[.*?\]\]",0.70),
    # Command Injection
    WAFRule("CMDI-001","Unix shell metachar + command",ThreatCategory.A03_CMDI,r"[;&|`]\s*(ls|cat|pwd|id|whoami|uname|ifconfig|netstat|ps|wget|curl|chmod|chown|rm|mv|cp|echo|bash|sh|python|perl|ruby|php)\b",0.90),
    WAFRule("CMDI-002","Command substitution $() ``",ThreatCategory.A03_CMDI,r"\$\([^)]+\)|`[^`]+`",0.85),
    WAFRule("CMDI-003","Windows cmd/powershell",ThreatCategory.A03_CMDI,r"(cmd\.exe|powershell|invoke-expression|iex\s*\(|certutil|bitsadmin|mshta|wscript|cscript)",0.90),
    WAFRule("CMDI-004","/etc/passwd /etc/shadow",ThreatCategory.A03_CMDI,r"/etc/(passwd|shadow|group|hosts|crontab|sudoers)",0.85),
    WAFRule("CMDI-005","Windows system files",ThreatCategory.A03_CMDI,r"(windows[\\/]system32|win\.ini|autoexec\.bat|boot\.ini|sam[\\/]|ntds\.dit)",0.85),
    # Path Traversal
    WAFRule("PT-001","../  traversal",ThreatCategory.PATH_TRAVERSAL,r"(\.\.[/\\]){2,}|(\.\.[/\\]){1,}.*(passwd|shadow|win\.ini|web\.config)",0.90),
    WAFRule("PT-002","Null byte in file extension",ThreatCategory.PATH_TRAVERSAL,r"\.php(\x00|%00|%2500)\.",0.95),
    WAFRule("PT-003","RFI http:// in file param",ThreatCategory.PATH_TRAVERSAL,r"(include|require|file|path|page|doc|src)\s*=\s*https?://",0.90),
    WAFRule("PT-004","/proc/self/ access",ThreatCategory.PATH_TRAVERSAL,r"/proc/self/(environ|cmdline|maps|fd)",0.95),
    # SSRF
    WAFRule("SSRF-001","Internal/loopback address",ThreatCategory.A10_SSRF,r"(https?://)(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|::1|169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",0.95),
    WAFRule("SSRF-002","Cloud metadata endpoint",ThreatCategory.A10_SSRF,r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|metadata\.azure\.internal",0.99),
    WAFRule("SSRF-003","file:// URI",ThreatCategory.A10_SSRF,r"file://",0.90),
    WAFRule("SSRF-004","dict:// gopher:// ftp://",ThreatCategory.A10_SSRF,r"(dict|gopher|ftp)://",0.85),
    # XXE
    WAFRule("XXE-001","DOCTYPE with ENTITY",ThreatCategory.A03_XXE,r"<!DOCTYPE\s+\w+\s*\[.*<!ENTITY",0.95),
    WAFRule("XXE-002","SYSTEM entity",ThreatCategory.A03_XXE,r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']",0.95),
    WAFRule("XXE-003","PUBLIC entity",ThreatCategory.A03_XXE,r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"']",0.90),
    # SSTI
    WAFRule("SSTI-001","Jinja2/Twig template expression",ThreatCategory.A03_SSTI,r"\{\{.{0,30}(config|self|request|class|mro|subclasses|__import__|os\.system|popen).{0,30}\}\}",0.90),
    WAFRule("SSTI-002","Arithmetic probe {{7*7}}",ThreatCategory.A03_SSTI,r"\{\{\s*\d+\s*[\*\+\-]\s*\d+\s*\}\}",0.80),
    WAFRule("SSTI-003","Ruby/ERB template injection",ThreatCategory.A03_SSTI,r"<%=.{0,30}(system|exec|`|IO\.popen).{0,30}%>",0.90),
    # CRLF / HTTP Smuggling
    WAFRule("CRLF-001","Encoded CRLF newline",ThreatCategory.HTTP_SMUGGLING,r"%0[dD]%0[aA]|%0[aA]%0[dD]|\r\n|\r|\n",0.85),
    # Open Redirect
    WAFRule("REDIR-001","External URL in redirect param",ThreatCategory.OPEN_REDIRECT,r"(redirect|return|next|url|goto|target|redir|dest)\s*=\s*https?://(?!localhost)",0.75),
    # Broken Access Control
    WAFRule("BAC-001","Numeric ID enumeration in sensitive path",ThreatCategory.A01_BROKEN_ACCESS_CONTROL,r"/(admin|user|account|profile|order|invoice|document|record|report)/\d{1,10}",0.55,apply_to=["path"]),
    WAFRule("BAC-002","Admin/config endpoint forced browsing",ThreatCategory.A01_BROKEN_ACCESS_CONTROL,r"/(admin|administrator|phpmyadmin|wp-admin|config|setup|install|backup|\.git|\.env|\.htaccess|web\.config)",0.70,apply_to=["path"]),
    # Cryptographic failures
    WAFRule("CRYPTO-001","Secret/token in URL query string",ThreatCategory.A02_CRYPTOGRAPHIC_FAILURE,r"[?&](password|passwd|pwd|token|api_key|apikey|secret|private_key|access_token)=",0.70,apply_to=["path","query"]),
    # Security Misconfiguration
    WAFRule("MISCONFIG-001","Debug/diagnostic endpoints",ThreatCategory.A05_MISCONFIGURATION,r"/(debug|test|dev|staging|phpinfo|server-status|actuator|metrics|swagger|api-docs|openapi)",0.60,apply_to=["path"]),
    WAFRule("MISCONFIG-002","Backup/config file access",ThreatCategory.A05_MISCONFIGURATION,r"\.(bak|old|orig|backup|swp|sql|db|sqlite|log|cfg|conf|ini|env|pem|key|crt|pfx)\b",0.65,apply_to=["path"]),
    WAFRule("MISCONFIG-003","Git/SVN/CI metadata",ThreatCategory.A05_MISCONFIGURATION,r"/(\.git|\.svn|\.hg|\.DS_Store|Thumbs\.db|web\.config|Dockerfile|docker-compose)",0.75,apply_to=["path"]),
    # Auth failure
    WAFRule("AUTH-001","SQL in username/password field",ThreatCategory.A07_AUTH_FAILURE,r"(username|user|email|login|pass|password)\s*=.*('|\"|--|#|/\*|;|union|select|or\s+1)",0.90),
    # Obfuscation
    WAFRule("OBF-001","Double URL encoding",ThreatCategory.PAYLOAD_OBFUSCATION,r"%25[0-9a-fA-F]{2}",0.70),
    WAFRule("OBF-002","Null byte injection",ThreatCategory.PAYLOAD_OBFUSCATION,r"%00|\\x00|\x00",0.75),
    WAFRule("OBF-003","Unicode full-width evasion",ThreatCategory.PAYLOAD_OBFUSCATION,r"[\uff01-\uff5e]",0.65),
    # Bots
    WAFRule("BOT-001","Known attack tool user-agent",ThreatCategory.BOT_TRAFFIC,r"(sqlmap|nikto|nmap|masscan|zgrab|w3af|burpsuite|dirbuster|gobuster|wfuzz|hydra|medusa|acunetix|netsparker|openvas|havij|skipfish|appscan|webinspect|nessus|vega|paros|zap)",0.99,apply_to=["user_agent"]),
    # LDAP
    WAFRule("LDAPI-001","LDAP filter metacharacters",ThreatCategory.A03_LDAPI,r"[)(|*\\]\s*(cn|uid|ou|dc|sn|mail|objectclass)\s*=",0.85),
]

class RuleEngine(BaseDetector):
    name = "rule_engine"
    def __init__(self, rules=None):
        self._rules = rules or RULES
        logger.info("RuleEngine loaded with %d rules", len(self._rules))

    def detect(self, nr, fv):
        results = []
        ing = nr.ingress
        field_map = {
            "all_inputs": nr.all_inputs_combined,
            "path": nr.decoded_path,
            "query": nr.decoded_query_string,
            "headers": " ".join(f"{k}: {v}" for k,v in nr.decoded_headers.items()),
            "body": nr.body_raw_decoded,
            "user_agent": ing.user_agent,
            "cookies": " ".join(f"{k}={v}" for k,v in nr.decoded_cookies.items()),
        }
        for rule in self._rules:
            targets = rule.apply_to if rule.apply_to != ["all_inputs"] else ["all_inputs"]
            for target in targets:
                text = field_map.get(target, "")
                if not text: continue
                m = rule.compiled.search(text)
                if m:
                    results.append(DetectionResult(
                        score=rule.score, matched=True, category=rule.category,
                        rule_id=rule.rule_id,
                        details=f"{rule.description} — matched in [{target}]",
                        evidence={"matched_text": m.group(0)[:200], "field": target, "rule_id": rule.rule_id},
                    ))
                    break
        if fv.encoding_depth > 1 and results:
            for r in results: r.score = min(1.0, r.score + 0.10)
        return results
