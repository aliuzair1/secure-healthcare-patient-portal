"""extractor.py — Feature Extraction Layer (Pipeline Step 3)"""
from __future__ import annotations
import math, re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List
from normalizer import NormalisedRequest
from logger import get_logger
logger = get_logger("extractor")

FEATURE_SCHEMA_VERSION = 1

@dataclass
class FeatureVector:
    schema_version: int = FEATURE_SCHEMA_VERSION
    method: str = ""; method_encoded: int = 0
    path_length: int = 0; path_depth: int = 0; path_entropy: float = 0.0
    query_param_count: int = 0; total_param_count: int = 0; query_entropy: float = 0.0
    body_size_bytes: int = 0; body_entropy: float = 0.0; body_type: str = ""; content_type: str = ""
    has_body: bool = False; has_file_upload: bool = False; has_xml: bool = False
    json_max_depth: int = 0; json_key_count: int = 0
    has_sql_keywords: bool = False; has_script_tags: bool = False
    has_shell_chars: bool = False; has_path_traversal: bool = False
    has_null_bytes: bool = False; has_crlf: bool = False; high_special_char_ratio: bool = False
    header_count: int = 0; user_agent_length: int = 0; has_user_agent: bool = False
    has_referer: bool = False; has_x_forwarded_for: bool = False; unusual_header_count: int = 0
    encoding_depth: int = 0; had_html_entities: bool = False; had_unicode_tricks: bool = False
    had_base64_payloads: bool = False; had_null_bytes: bool = False
    repeated_param_names: bool = False; max_param_value_length: int = 0; max_param_name_length: int = 0
    session_request_count: int = 0; session_age_seconds: float = 0.0; failed_auth_count: int = 0
    is_known_bot_ua: bool = False; ip_request_rate: float = 0.0; distinct_paths_count: int = 0
    all_inputs: str = ""
    numeric_vector: List[float] = field(default_factory=list)
    numeric_feature_names: List[str] = field(default_factory=list)

_METHOD_MAP = {"GET":0,"POST":1,"PUT":2,"DELETE":3,"PATCH":4}
_SQL_KW_RE = re.compile(r"\b(select|insert|update|delete|drop|create|alter|union|exec|execute|xp_|sp_|information_schema|sysobjects|benchmark|sleep|waitfor|load_file|outfile|dumpfile|having|group\s+by|order\s+by)\b", re.IGNORECASE)
_SCRIPT_RE = re.compile(r"<\s*script|javascript\s*:|on\w+\s*=|eval\s*\(|expression\s*\(|vbscript\s*:|data\s*:\s*text/html", re.IGNORECASE)
_SHELL_RE = re.compile(r"[;|&`$(){}<>]")
_PATH_TRAV_RE = re.compile(r"\.\.[/\\]|\.\./|%2e%2e[%2f%5c]", re.IGNORECASE)
_CRLF_RE = re.compile(r"%0[dD]%0[aA]|\r\n|\r|\n")
_BOT_UA_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|w3af|burpsuite|dirbuster|gobuster|wfuzz|hydra|medusa|acunetix|netsparker|qualys|openvas|havij|python-requests/[0-1]\.|curl/[0-6]\.|libwww|wget|scrapy|bot|crawler|spider|scraper|fetch|heritrix|nutch)", re.IGNORECASE)
_UNUSUAL_HDR = frozenset(["x-custom-ip","x-originating-ip","x-remote-ip","x-remote-addr","x-client-ip","x-host","x-forwarded-host","x-rewrite-url","x-original-url"])

def _entropy(s):
    if not s: return 0.0
    c = Counter(s); l = len(s)
    return -sum((v/l)*math.log2(v/l) for v in c.values())

def _json_stats(obj, depth=0):
    if isinstance(obj, dict):
        md, cnt = depth, len(obj)
        for v in obj.values():
            d2, c2 = _json_stats(v, depth+1); md = max(md,d2); cnt += c2
        return md, cnt
    if isinstance(obj, list):
        md, cnt = depth, 0
        for v in obj[:100]:
            d2, c2 = _json_stats(v, depth+1); md = max(md,d2); cnt += c2
        return md, cnt
    return depth, 0

def extract_features(nr: NormalisedRequest) -> FeatureVector:
    fv = FeatureVector()
    ing = nr.ingress
    fv.method = ing.method; fv.method_encoded = _METHOD_MAP.get(ing.method, 5)
    fv.path_length = len(nr.decoded_path); fv.path_depth = nr.decoded_path.count("/")
    fv.path_entropy = _entropy(nr.decoded_path)
    fv.query_param_count = len(ing.query_params); fv.total_param_count = len(nr.params)
    fv.query_entropy = _entropy(nr.decoded_query_string)
    fv.has_body = bool(ing.raw_body); fv.body_size_bytes = ing.content_length
    fv.body_entropy = _entropy(nr.body_raw_decoded[:8192])
    fv.body_type = nr.body_type; fv.content_type = ing.content_type
    fv.has_file_upload = "multipart" in ing.content_type.lower()
    fv.has_xml = nr.body_type == "xml" or "xml" in ing.content_type.lower()
    if nr.body_type == "json" and nr.body_parsed is not None:
        fv.json_max_depth, fv.json_key_count = _json_stats(nr.body_parsed)
    fv.all_inputs = nr.all_inputs_combined
    c = nr.all_inputs_combined
    fv.has_sql_keywords = bool(_SQL_KW_RE.search(c))
    fv.has_script_tags = bool(_SCRIPT_RE.search(c))
    fv.has_shell_chars = bool(_SHELL_RE.search(c))
    fv.has_path_traversal = bool(_PATH_TRAV_RE.search(c))
    fv.has_null_bytes = nr.had_null_bytes or "\x00" in c
    fv.has_crlf = bool(_CRLF_RE.search(c))
    special = sum(1 for ch in c if not ch.isalnum() and ch not in " -_.")
    fv.high_special_char_ratio = (special/len(c) > 0.30) if c else False
    if nr.params:
        nl = [len(k) for k in nr.params]; vl = [len(v) for vs in nr.params.values() for v in vs]
        fv.max_param_name_length = max(nl) if nl else 0
        fv.max_param_value_length = max(vl) if vl else 0
        fv.repeated_param_names = any(len(v)>1 for v in nr.params.values())
    fv.header_count = len(nr.decoded_headers)
    fv.has_user_agent = bool(ing.user_agent); fv.user_agent_length = len(ing.user_agent)
    fv.has_referer = bool(ing.referer)
    fv.has_x_forwarded_for = "x-forwarded-for" in nr.decoded_headers
    fv.unusual_header_count = sum(1 for h in nr.decoded_headers if h.lower() in _UNUSUAL_HDR)
    fv.is_known_bot_ua = bool(_BOT_UA_RE.search(ing.user_agent))
    fv.encoding_depth = nr.encoding_depth; fv.had_html_entities = nr.had_html_entities
    fv.had_unicode_tricks = nr.had_unicode_tricks; fv.had_base64_payloads = nr.had_base64_payloads
    fv.had_null_bytes = nr.had_null_bytes
    nf = [("method_encoded",float(fv.method_encoded)),("path_length",float(fv.path_length)),
          ("path_depth",float(fv.path_depth)),("path_entropy",fv.path_entropy),
          ("query_param_count",float(fv.query_param_count)),("total_param_count",float(fv.total_param_count)),
          ("query_entropy",fv.query_entropy),("body_size_bytes",float(fv.body_size_bytes)),
          ("body_entropy",fv.body_entropy),("has_sql_keywords",float(fv.has_sql_keywords)),
          ("has_script_tags",float(fv.has_script_tags)),("has_shell_chars",float(fv.has_shell_chars)),
          ("has_path_traversal",float(fv.has_path_traversal)),("has_null_bytes",float(fv.has_null_bytes)),
          ("has_crlf",float(fv.has_crlf)),("high_special_char_ratio",float(fv.high_special_char_ratio)),
          ("encoding_depth",float(fv.encoding_depth)),("had_html_entities",float(fv.had_html_entities)),
          ("had_unicode_tricks",float(fv.had_unicode_tricks)),("had_base64_payloads",float(fv.had_base64_payloads)),
          ("header_count",float(fv.header_count)),("has_user_agent",float(fv.has_user_agent)),
          ("user_agent_length",float(fv.user_agent_length)),("unusual_header_count",float(fv.unusual_header_count)),
          ("max_param_value_length",float(fv.max_param_value_length)),
          ("json_max_depth",float(fv.json_max_depth)),("json_key_count",float(fv.json_key_count)),
          ("is_known_bot_ua",float(fv.is_known_bot_ua)),("repeated_param_names",float(fv.repeated_param_names)),
          ("has_body",float(fv.has_body))]
    fv.numeric_feature_names = [n for n,_ in nf]; fv.numeric_vector = [v for _,v in nf]
    return fv
