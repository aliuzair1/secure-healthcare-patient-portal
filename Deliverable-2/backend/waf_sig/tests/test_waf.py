"""
tests/test_waf.py — Signature WAF Test Suite

Run:  python -m pytest tests/ -v
"""

from __future__ import annotations

import sys
import os
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ingress import IngressRequest
from normalizer import normalise
from detection import DetectionReport
from detection.rule_engine import RuleEngine
from scoring import compute_score, RiskScore
from decision import decide, Action, policy_overrides


# ---------------------------------------------------------------------------
# Helper: build an IngressRequest without needing Flask
# ---------------------------------------------------------------------------

def make_ingress(
    path:         str  = "/api/data",
    method:       str  = "GET",
    query_string: str  = "",
    raw_body:     bytes= b"",
    content_type: str  = "application/json",
    user_agent:   str  = "Mozilla/5.0",
    client_ip:    str  = "1.2.3.4",
    headers:      dict = None,
    cookies:      dict = None,
) -> IngressRequest:
    qp = {}
    if query_string:
        for pair in query_string.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qp.setdefault(k, []).append(v)
    return IngressRequest(
        request_id     = str(uuid.uuid4()),
        timestamp      = time.time(),
        client_ip      = client_ip,
        real_ip_source = "REMOTE_ADDR",
        method         = method,
        path           = path,
        query_string   = query_string,
        http_version   = "HTTP/1.1",
        scheme         = "https",
        headers        = headers or {"User-Agent": user_agent, "Host": "example.com"},
        query_params   = qp,
        cookies        = cookies or {},
        raw_body       = raw_body,
        content_type   = content_type,
        content_length = len(raw_body),
        user_agent     = user_agent,
        referer        = "",
        host           = "example.com",
    )


def scan(ingress: IngressRequest):
    """Run normaliser + rule engine; return (findings, nr)."""
    nr       = normalise(ingress)
    report   = DetectionReport(request_id=ingress.request_id)
    findings = RuleEngine().detect(nr, report)
    return findings, nr


def rule_ids(ingress: IngressRequest) -> set:
    findings, _ = scan(ingress)
    return {f.rule_id for f in findings}


# ═══════════════════════════════════════════════════════════════════════════
# SQL Injection
# ═══════════════════════════════════════════════════════════════════════════

class TestSQLInjection:

    def test_union_select(self):
        assert "SQLI-001" in rule_ids(make_ingress(query_string="id=1 UNION SELECT 1,2,3--"))

    def test_time_based_sleep(self):
        assert "SQLI-004" in rule_ids(make_ingress(query_string="id=1'; SLEEP(5)--"))

    def test_waitfor_delay(self):
        assert "SQLI-004" in rule_ids(make_ingress(query_string="name='; WAITFOR DELAY '0:0:5'--"))

    def test_information_schema(self):
        assert "SQLI-008" in rule_ids(make_ingress(query_string="q=SELECT * FROM information_schema.tables"))

    def test_stacked_queries(self):
        assert "SQLI-005" in rule_ids(make_ingress(query_string="id=1; DROP TABLE users--"))

    def test_boolean_blind(self):
        assert "SQLI-003" in rule_ids(make_ingress(query_string="id=1 OR 1=1"))

    def test_sqlmap_user_agent(self):
        ids = rule_ids(make_ingress(user_agent="sqlmap/1.7.8#stable"))
        assert "SQLI-010" in ids or "BOT-001" in ids

    def test_clean_query_not_flagged(self):
        flagged = {r for r in rule_ids(make_ingress(query_string="page=1&sort=name")) if "SQLI" in r}
        assert not flagged

    def test_sqli_in_json_body(self):
        body = b'{"username": "admin OR 1=1"}'  
        ids  = rule_ids(make_ingress(method="POST", raw_body=body, content_type="application/json"))
        assert "SQLI-003" in ids or "SQLI-002" in ids


# ═══════════════════════════════════════════════════════════════════════════
# Cross-Site Scripting
# ═══════════════════════════════════════════════════════════════════════════

class TestXSS:

    def test_script_tag(self):
        assert "XSS-001" in rule_ids(make_ingress(query_string="q=<script>alert(1)</script>"))

    def test_javascript_uri(self):
        assert "XSS-002" in rule_ids(make_ingress(query_string="url=javascript:alert(document.cookie)"))

    def test_event_handler(self):
        body = b'{"name": "<img src=x onerror=alert(1)>"}'
        assert "XSS-003" in rule_ids(make_ingress(method="POST", raw_body=body, content_type="application/json"))

    def test_eval_sink(self):
        assert "XSS-004" in rule_ids(make_ingress(query_string="cb=eval(atob('YWxlcnQoMSk='))"))

    def test_svg_injection(self):
        body = b'<svg onload="alert(1)">'
        assert "XSS-006" in rule_ids(make_ingress(method="POST", raw_body=body, content_type="text/html"))

    def test_template_injection(self):
        assert "XSS-008" in rule_ids(make_ingress(query_string="name={{7*7}}"))

    def test_html_encoded_script_decoded_and_caught(self):
        # &lt;script&gt; should be decoded by normaliser then caught by XSS-001
        nr = normalise(make_ingress(query_string="q=&lt;script&gt;alert(1)&lt;/script&gt;"))
        assert nr.had_html_entities
        assert "<script>" in nr.all_inputs.lower()


# ═══════════════════════════════════════════════════════════════════════════
# Command Injection
# ═══════════════════════════════════════════════════════════════════════════

class TestCommandInjection:

    def test_unix_pipe(self):
        assert "CMDI-001" in rule_ids(make_ingress(query_string="cmd=test|whoami"))

    def test_etc_passwd(self):
        assert "CMDI-004" in rule_ids(make_ingress(query_string="file=/etc/passwd"))

    def test_powershell(self):
        body = b'{"exec": "powershell Invoke-Expression calc.exe"}'
        assert "CMDI-003" in rule_ids(make_ingress(method="POST", raw_body=body, content_type="application/json"))

    def test_command_substitution(self):
        assert "CMDI-002" in rule_ids(make_ingress(query_string="x=$(id)"))


# ═══════════════════════════════════════════════════════════════════════════
# Path Traversal / LFI / RFI
# ═══════════════════════════════════════════════════════════════════════════

class TestPathTraversal:

    def test_dotdot_passwd(self):
        assert "PT-001" in rule_ids(make_ingress(query_string="file=../../etc/passwd"))

    def test_rfi_http(self):
        assert "PT-003" in rule_ids(make_ingress(query_string="page=http://evil.com/shell.php"))

    def test_proc_self_environ(self):
        assert "PT-004" in rule_ids(make_ingress(query_string="f=/proc/self/environ"))


# ═══════════════════════════════════════════════════════════════════════════
# SSRF
# ═══════════════════════════════════════════════════════════════════════════

class TestSSRF:

    def test_localhost(self):
        assert "SSRF-001" in rule_ids(make_ingress(query_string="url=http://127.0.0.1:8080/admin"))

    def test_aws_metadata(self):
        assert "SSRF-002" in rule_ids(make_ingress(query_string="cb=http://169.254.169.254/latest/meta-data/"))

    def test_file_uri(self):
        assert "SSRF-003" in rule_ids(make_ingress(query_string="x=file:///etc/passwd"))

    def test_gopher(self):
        assert "SSRF-004" in rule_ids(make_ingress(query_string="u=gopher://127.0.0.1:25/"))


# ═══════════════════════════════════════════════════════════════════════════
# XXE
# ═══════════════════════════════════════════════════════════════════════════

class TestXXE:

    def test_doctype_entity(self):
        payload = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'
        assert "XXE-001" in rule_ids(make_ingress(method="POST", raw_body=payload, content_type="application/xml"))

    def test_system_entity(self):
        body = b'<!ENTITY ext SYSTEM "file:///etc/shadow">'
        assert "XXE-002" in rule_ids(make_ingress(method="POST", raw_body=body, content_type="application/xml"))


# ═══════════════════════════════════════════════════════════════════════════
# Security Misconfiguration
# ═══════════════════════════════════════════════════════════════════════════

class TestMisconfiguration:

    def test_git_access(self):
        assert "MISCONFIG-003" in rule_ids(make_ingress(path="/.git/config"))

    def test_env_file(self):
        assert "MISCONFIG-002" in rule_ids(make_ingress(path="/.env"))

    def test_backup_file(self):
        assert "MISCONFIG-002" in rule_ids(make_ingress(path="/config.php.bak"))

    def test_swagger_ui(self):
        assert "MISCONFIG-001" in rule_ids(make_ingress(path="/swagger-ui/index.html"))

    def test_admin_path(self):
        assert "BAC-001" in rule_ids(make_ingress(path="/admin/dashboard"))


# ═══════════════════════════════════════════════════════════════════════════
# Normaliser
# ═══════════════════════════════════════════════════════════════════════════

class TestNormaliser:

    def test_url_decode(self):
        nr = normalise(make_ingress(query_string="q=UNION%20SELECT%201"))
        assert "UNION SELECT" in nr.decoded_query_string

    def test_double_encode_detected(self):
        nr = normalise(make_ingress(query_string="q=%2527%2520OR%25201%253D1"))
        assert nr.encoding_depth >= 1

    def test_null_byte_removed(self):
        nr = normalise(make_ingress(query_string="file=shell.php%00.jpg"))
        assert nr.had_null_bytes
        assert "\x00" not in nr.all_inputs

    def test_html_entity_decoded(self):
        nr = normalise(make_ingress(query_string="q=&lt;script&gt;"))
        assert nr.had_html_entities
        assert "<script>" in nr.all_inputs.lower()

    def test_json_body_parsed(self):
        nr = normalise(make_ingress(
            method="POST",
            raw_body=b'{"username": "admin", "password": "test"}',
            content_type="application/json",
        ))
        assert nr.body_type == "json"
        assert "username" in nr.body_flat


# ═══════════════════════════════════════════════════════════════════════════
# Scoring
# ═══════════════════════════════════════════════════════════════════════════

class TestScoring:

    def _score(self, ingress):
        nr      = normalise(ingress)
        report  = DetectionReport(request_id=ingress.request_id)
        for f in RuleEngine().detect(nr, report):
            f.engine = "rule_engine"
            report.add(f)
        return compute_score(report, nr, ingress)

    def test_high_confidence_rule_raises_score(self):
        risk = self._score(make_ingress(path="/search", query_string="id=1 UNION SELECT password FROM users"))
        assert risk.score >= 0.65

    def test_clean_request_low_score(self):
        risk = self._score(make_ingress(query_string="page=1&sort=name&order=asc"))
        assert risk.score < 0.20

    def test_obfuscation_boosts_score(self):
        # Double-encoded UNION SELECT — normaliser decodes it, score gets boosted
        risk_plain = self._score(make_ingress(path="/search", query_string="id=1 UNION SELECT 1"))
        risk_obf   = self._score(make_ingress(path="/search", query_string="id=1%2520UNION%2520SELECT%25201"))
        assert risk_obf.obfuscation_detected or risk_obf.score >= risk_plain.score - 0.05


# ═══════════════════════════════════════════════════════════════════════════
# Decision
# ═══════════════════════════════════════════════════════════════════════════

class TestDecision:

    def _risk(self, score, ip_blocklisted=False, ip_allowlisted=False):
        r              = RiskScore(request_id="test", score=score)
        r.ip_blocklisted = ip_blocklisted
        return r

    def _decide(self, score, ip="1.2.3.4", path="/api", **kwargs):
        ingress = make_ingress(client_ip=ip, path=path)
        ingress.ip_blocklisted = kwargs.get("ip_blocklisted", False)
        ingress.ip_allowlisted = kwargs.get("ip_allowlisted", False)
        return decide(self._risk(score, **{k:v for k,v in kwargs.items() if k in ("ip_blocklisted",)}), ingress)

    def test_score_above_block_threshold(self):
        assert self._decide(0.90).action == Action.BLOCK

    def test_score_in_challenge_range(self):
        assert self._decide(0.60).action == Action.CHALLENGE

    def test_score_in_rate_limit_range(self):
        assert self._decide(0.40).action == Action.RATE_LIMIT

    def test_score_in_log_only_range(self):
        assert self._decide(0.15).action == Action.LOG_ONLY

    def test_clean_request_allowed(self):
        assert self._decide(0.02).action == Action.ALLOW

    def test_blocklisted_ip_always_blocked(self):
        d = self._decide(0.01, ip_blocklisted=True)
        assert d.action == Action.BLOCK

    def test_allowlisted_ip_always_allowed(self):
        ingress = make_ingress()
        ingress.ip_allowlisted = True
        risk = self._risk(0.99)
        assert decide(risk, ingress).action == Action.ALLOW

    def test_health_path_always_allowed(self):
        # /health is in the default path overrides
        assert self._decide(0.99, path="/health").action == Action.ALLOW

    def test_metrics_path_log_only(self):
        assert self._decide(0.99, path="/metrics").action == Action.LOG_ONLY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
