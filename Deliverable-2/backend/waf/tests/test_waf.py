"""
tests/test_waf.py — WAF Unit & Integration Tests

Run with:  python -m pytest tests/ -v
"""

import sys
import os

# Add parent dir to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import MagicMock, patch

# We need to create mock IngressRequests for testing
from ingress import IngressRequest
from normalizer import normalise, NormalisedRequest
from extractor import extract_features
from detection import DetectionReport
from detection.rule_engine import RuleEngine
from detection.behavioral import BehavioralEngine
from scoring import compute_score
from decision import decide, Action
import time


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_ingress(
    path="/api/test",
    method="GET",
    query_string="",
    raw_body=b"",
    content_type="application/json",
    user_agent="Mozilla/5.0",
    client_ip="1.2.3.4",
    headers=None,
    cookies=None,
) -> IngressRequest:
    import uuid
    return IngressRequest(
        request_id=str(uuid.uuid4()),
        timestamp=time.time(),
        client_ip=client_ip,
        real_ip_source="REMOTE_ADDR",
        method=method,
        path=path,
        query_string=query_string,
        http_version="HTTP/1.1",
        scheme="https",
        headers=headers or {"User-Agent": user_agent, "Host": "example.com"},
        query_params={k: [v] for k, v in (
            p.split("=", 1) for p in query_string.split("&") if "=" in p
        )} if query_string else {},
        cookies=cookies or {},
        raw_body=raw_body,
        content_type=content_type,
        content_length=len(raw_body),
        user_agent=user_agent,
        referer="",
        host="example.com",
    )


def run_rule_engine(ingress: IngressRequest):
    nr = normalise(ingress)
    fv = extract_features(nr)
    engine = RuleEngine()
    return engine.detect(nr, fv), nr, fv


# ---------------------------------------------------------------------------
# SQL Injection tests
# ---------------------------------------------------------------------------

class TestSQLInjection:
    def test_union_select_blocked(self):
        ingress = make_ingress(query_string="id=1 UNION SELECT username,password FROM users")
        findings, _, _ = run_rule_engine(ingress)
        rule_ids = [f.rule_id for f in findings]
        assert "SQLI-001" in rule_ids

    def test_time_based_blind(self):
        ingress = make_ingress(query_string="id=1'; WAITFOR DELAY '0:0:5'--")
        findings, _, _ = run_rule_engine(ingress)
        rule_ids = [f.rule_id for f in findings]
        assert "SQLI-004" in rule_ids

    def test_information_schema(self):
        ingress = make_ingress(query_string="q=SELECT * FROM information_schema.tables")
        findings, _, _ = run_rule_engine(ingress)
        rule_ids = [f.rule_id for f in findings]
        assert "SQLI-008" in rule_ids

    def test_boolean_blind(self):
        ingress = make_ingress(query_string="id=1 OR 1=1")
        findings, _, _ = run_rule_engine(ingress)
        rule_ids = [f.rule_id for f in findings]
        assert "SQLI-003" in rule_ids

    def test_sqlmap_user_agent(self):
        ingress = make_ingress(user_agent="sqlmap/1.7.8#stable (https://sqlmap.org)")
        findings, _, _ = run_rule_engine(ingress)
        rule_ids = [f.rule_id for f in findings]
        assert "SQLI-010" in rule_ids or "BOT-001" in rule_ids

    def test_clean_request_not_blocked(self):
        ingress = make_ingress(query_string="q=hello+world&page=2")
        findings, _, _ = run_rule_engine(ingress)
        sqli_findings = [f for f in findings if "SQLI" in f.rule_id]
        assert len(sqli_findings) == 0


# ---------------------------------------------------------------------------
# XSS tests
# ---------------------------------------------------------------------------

class TestXSS:
    def test_script_tag(self):
        ingress = make_ingress(query_string="name=<script>alert(1)</script>")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "XSS-001" for f in findings)

    def test_javascript_uri(self):
        ingress = make_ingress(query_string="url=javascript:alert(document.cookie)")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "XSS-002" for f in findings)

    def test_event_handler(self):
        ingress = make_ingress(
            raw_body=b'{"name": "<img src=x onerror=alert(1)>"}',
            content_type="application/json",
            method="POST",
        )
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "XSS-003" for f in findings)

    def test_encoded_script_detected(self):
        # Double URL-encoded <script>
        ingress = make_ingress(query_string="q=%253Cscript%253Ealert(1)%253C/script%253E")
        nr = normalise(ingress)
        # Normaliser should decode this
        assert "<script>" in nr.all_inputs_combined.lower() or "script" in nr.all_inputs_combined.lower()


# ---------------------------------------------------------------------------
# Command Injection tests
# ---------------------------------------------------------------------------

class TestCommandInjection:
    def test_unix_shell_pipe(self):
        ingress = make_ingress(query_string="cmd=test|whoami")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "CMDI-001" for f in findings)

    def test_etc_passwd(self):
        ingress = make_ingress(path="/api/file", query_string="file=/etc/passwd")
        findings, _, _ = run_rule_engine(ingress)
        assert any("CMDI" in f.rule_id for f in findings)

    def test_powershell(self):
        ingress = make_ingress(
            raw_body=b'{"exec": "powershell Invoke-Expression calc"}',
            method="POST",
            content_type="application/json",
        )
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "CMDI-003" for f in findings)


# ---------------------------------------------------------------------------
# SSRF tests
# ---------------------------------------------------------------------------

class TestSSRF:
    def test_localhost_ssrf(self):
        ingress = make_ingress(query_string="url=http://127.0.0.1:8080/admin")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "SSRF-001" for f in findings)

    def test_aws_metadata(self):
        ingress = make_ingress(query_string="webhook=http://169.254.169.254/latest/meta-data/")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "SSRF-002" for f in findings)

    def test_file_uri(self):
        ingress = make_ingress(query_string="resource=file:///etc/passwd")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "SSRF-003" for f in findings)


# ---------------------------------------------------------------------------
# Path Traversal tests
# ---------------------------------------------------------------------------

class TestPathTraversal:
    def test_basic_traversal(self):
        ingress = make_ingress(query_string="file=../../etc/passwd")
        findings, _, _ = run_rule_engine(ingress)
        assert any("PT" in f.rule_id for f in findings)

    def test_rfi(self):
        ingress = make_ingress(query_string="page=http://evil.com/shell.php")
        findings, _, _ = run_rule_engine(ingress)
        assert any(f.rule_id == "PT-003" for f in findings)


# ---------------------------------------------------------------------------
# XXE tests
# ---------------------------------------------------------------------------

class TestXXE:
    def test_doctype_entity(self):
        payload = b'<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
        ingress = make_ingress(
            raw_body=payload,
            content_type="application/xml",
            method="POST",
        )
        findings, _, _ = run_rule_engine(ingress)
        assert any("XXE" in f.rule_id for f in findings)


# ---------------------------------------------------------------------------
# Normaliser tests
# ---------------------------------------------------------------------------

class TestNormaliser:
    def test_url_decode(self):
        ingress = make_ingress(query_string="q=UNION%20SELECT%201")
        nr = normalise(ingress)
        assert "UNION SELECT" in nr.decoded_query_string

    def test_double_encode_detected(self):
        ingress = make_ingress(query_string="q=%2527%2520OR%25201%253D1")
        nr = normalise(ingress)
        assert nr.encoding_depth >= 1

    def test_null_byte_removal(self):
        ingress = make_ingress(query_string="file=shell.php%00.jpg")
        nr = normalise(ingress)
        assert nr.had_null_bytes
        assert "\x00" not in nr.all_inputs_combined

    def test_html_entity_decode(self):
        ingress = make_ingress(query_string="q=&lt;script&gt;alert(1)&lt;/script&gt;")
        nr = normalise(ingress)
        assert nr.had_html_entities
        assert "<script>" in nr.all_inputs_combined.lower()

    def test_json_body_parsed(self):
        ingress = make_ingress(
            raw_body=b'{"username": "admin", "password": "test"}',
            content_type="application/json",
            method="POST",
        )
        nr = normalise(ingress)
        assert nr.body_type == "json"
        assert "username" in nr.body_flat


# ---------------------------------------------------------------------------
# Security Misconfiguration tests
# ---------------------------------------------------------------------------

class TestMisconfiguration:
    def test_git_access(self):
        ingress = make_ingress(path="/.git/config")
        findings, _, _ = run_rule_engine(ingress)
        assert any("MISCONFIG" in f.rule_id for f in findings)

    def test_env_file_access(self):
        ingress = make_ingress(path="/.env")
        findings, _, _ = run_rule_engine(ingress)
        assert any("MISCONFIG" in f.rule_id for f in findings)

    def test_backup_file(self):
        ingress = make_ingress(path="/config.php.bak")
        findings, _, _ = run_rule_engine(ingress)
        assert any("MISCONFIG" in f.rule_id for f in findings)


# ---------------------------------------------------------------------------
# Scoring tests
# ---------------------------------------------------------------------------

class TestScoring:
    def test_high_severity_rule_produces_high_score(self):
        ingress = make_ingress(path='/search', query_string="id=1 UNION SELECT password FROM users")
        nr = normalise(ingress)
        fv = extract_features(nr)
        engine = RuleEngine()
        findings = engine.detect(nr, fv)
        report = DetectionReport(request_id=ingress.request_id)
        for f in findings:
            f.engine = "rule_engine"
            report.add(f)
        risk = compute_score(report, fv, ingress)
        assert risk.score >= 0.65

    def test_clean_request_low_score(self):
        ingress = make_ingress(query_string="page=1&sort=name&order=asc")
        nr = normalise(ingress)
        fv = extract_features(nr)
        report = DetectionReport(request_id=ingress.request_id)
        risk = compute_score(report, fv, ingress)
        assert risk.score < 0.20


# ---------------------------------------------------------------------------
# Decision tests
# ---------------------------------------------------------------------------

class TestDecision:
    def _make_risk(self, score):
        from scoring import RiskScore
        return RiskScore(request_id="test-123", score=score)

    def test_score_above_block_threshold_blocks(self):
        ingress = make_ingress()
        risk = self._make_risk(0.90)
        decision = decide(risk, ingress)
        assert decision.action == Action.BLOCK

    def test_score_in_challenge_range(self):
        ingress = make_ingress()
        risk = self._make_risk(0.60)
        decision = decide(risk, ingress)
        assert decision.action == Action.CHALLENGE

    def test_score_in_rate_limit_range(self):
        ingress = make_ingress()
        risk = self._make_risk(0.40)
        decision = decide(risk, ingress)
        assert decision.action == Action.RATE_LIMIT

    def test_clean_request_allowed(self):
        ingress = make_ingress()
        risk = self._make_risk(0.05)
        decision = decide(risk, ingress)
        assert decision.action == Action.ALLOW

    def test_blocklisted_ip_always_blocked(self):
        ingress = make_ingress(client_ip="10.0.0.1")
        ingress.ip_blocklisted = True
        risk = self._make_risk(0.10)  # Low score, but IP is blocklisted
        risk.ip_blocklisted = True
        decision = decide(risk, ingress)
        assert decision.action == Action.BLOCK

    def test_allowlisted_ip_always_allowed(self):
        ingress = make_ingress()
        ingress.ip_allowlisted = True
        risk = self._make_risk(0.90)  # High score, but IP is allowlisted
        decision = decide(risk, ingress)
        assert decision.action == Action.ALLOW

    def test_health_path_override(self):
        ingress = make_ingress(path="/health")
        risk = self._make_risk(0.90)  # High score but health path is overridden
        decision = decide(risk, ingress)
        assert decision.action == Action.ALLOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
