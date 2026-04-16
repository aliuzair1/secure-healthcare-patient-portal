"""normalizer.py — Request Normalisation Layer (Pipeline Step 2)"""
from __future__ import annotations
import base64, html, json, re, unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote_plus
from ingress import IngressRequest
from logger import get_logger
logger = get_logger("normalizer")

MAX_DECODE_PASSES = 3
MAX_BODY_SIZE = 1 * 1024 * 1024

@dataclass
class NormalisedRequest:
    ingress: IngressRequest
    decoded_path: str = ""
    decoded_query_string: str = ""
    params: Dict[str, List[str]] = field(default_factory=dict)
    decoded_headers: Dict[str, str] = field(default_factory=dict)
    decoded_cookies: Dict[str, str] = field(default_factory=dict)
    body_type: str = "unknown"
    body_parsed: Any = None
    body_flat: Dict[str, str] = field(default_factory=dict)
    body_raw_decoded: str = ""
    encoding_depth: int = 0
    had_null_bytes: bool = False
    had_unicode_tricks: bool = False
    had_html_entities: bool = False
    had_base64_payloads: bool = False
    all_inputs_combined: str = ""

_NULL_RE = re.compile(r"\x00+")
_HTML_ENTITY_RE = re.compile(r"&[a-zA-Z]{2,8};|&#\d{1,6};|&#x[0-9a-fA-F]{1,6};")
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_COMMENT_SQL_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_UNICODE_COLLAPSE = str.maketrans(
    "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ０１２３４５６７８９",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
)

def _iter_url_decode(s):
    depth = 0
    for _ in range(MAX_DECODE_PASSES):
        d = unquote_plus(s)
        if d == s: break
        s = d; depth += 1
    return s, depth

def _html_decode(s):
    has = bool(_HTML_ENTITY_RE.search(s))
    return html.unescape(s), has

def _unicode_norm(s):
    n = unicodedata.normalize("NFKC", s).translate(_UNICODE_COLLAPSE)
    return n, n != s

def _strip_null(s):
    c = _NULL_RE.sub("", s)
    return c, c != s

def _try_b64(s):
    found = False
    def _r(m):
        nonlocal found
        blob = m.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            d = base64.b64decode(padded).decode("utf-8","replace")
            if d.isprintable() or any(c.isalpha() for c in d):
                found = True; return d
        except Exception: pass
        return blob
    return _BASE64_RE.sub(_r, s), found

def _blank():
    return {"encoding_depth":0,"had_null_bytes":False,"had_unicode_tricks":False,
            "had_html_entities":False,"had_base64_payloads":False}

def _merge(a, b):
    return {"encoding_depth":max(a["encoding_depth"],b["encoding_depth"]),
            "had_null_bytes":a["had_null_bytes"] or b["had_null_bytes"],
            "had_unicode_tricks":a["had_unicode_tricks"] or b["had_unicode_tricks"],
            "had_html_entities":a["had_html_entities"] or b["had_html_entities"],
            "had_base64_payloads":a["had_base64_payloads"] or b["had_base64_payloads"]}

def _full_norm(s):
    sig = _blank()
    s, d = _iter_url_decode(s); sig["encoding_depth"] = d
    s, he = _html_decode(s); sig["had_html_entities"] = he
    s, nb = _strip_null(s); sig["had_null_bytes"] = nb
    s, uc = _unicode_norm(s); sig["had_unicode_tricks"] = uc
    s, b64 = _try_b64(s); sig["had_base64_payloads"] = b64
    s = _COMMENT_SQL_RE.sub(" ", s)
    return s, sig

def _flatten_json(obj, prefix="", depth=0):
    r = {}
    if depth > 8: r[prefix] = str(obj); return r
    if isinstance(obj, dict):
        for k, v in obj.items():
            r.update(_flatten_json(v, f"{prefix}.{k}" if prefix else k, depth+1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            r.update(_flatten_json(v, f"{prefix}[{i}]", depth+1))
    else:
        r[prefix] = str(obj)
    return r

def _parse_body(raw_body, content_type):
    if not raw_body: return "empty", None, {}, ""
    body_bytes = raw_body[:MAX_BODY_SIZE]
    try: raw_str = body_bytes.decode("utf-8","replace")
    except Exception: raw_str = repr(body_bytes)
    ct = content_type.lower().split(";")[0].strip()
    if "json" in ct or raw_str.lstrip().startswith(("{","[")):
        try:
            p = json.loads(raw_str)
            return "json", p, _flatten_json(p), raw_str
        except (json.JSONDecodeError, ValueError): pass
    if "form" in ct or "x-www-form-urlencoded" in ct:
        try:
            p = parse_qs(raw_str, keep_blank_values=True)
            return "form", p, {k:" ".join(v) for k,v in p.items()}, raw_str
        except Exception: pass
    if "xml" in ct: return "xml", None, {"__xml_body": raw_str}, raw_str
    if "multipart" in ct: return "raw", None, {"__multipart_raw": raw_str[:2048]}, raw_str
    return "raw", None, {"__raw_body": raw_str}, raw_str

def normalise(ingress: IngressRequest) -> NormalisedRequest:
    sig = _blank()
    path, ps = _full_norm(ingress.path); sig = _merge(sig, ps)
    qs, qs_s = _full_norm(ingress.query_string); sig = _merge(sig, qs_s)
    params: Dict[str, List[str]] = {}
    for k, vals in ingress.query_params.items():
        dk, _ = _full_norm(k)
        dvs = []
        for v in vals:
            dv, vs = _full_norm(v); sig = _merge(sig, vs); dvs.append(dv)
        params[dk] = dvs
    decoded_headers = {}
    for k, v in ingress.headers.items():
        dk = k.lower().strip()
        dv, hs = _full_norm(v); sig = _merge(sig, hs)
        decoded_headers[dk] = dv
    decoded_cookies = {}
    for k, v in ingress.cookies.items():
        dk, _ = _full_norm(k)
        dv, cs = _full_norm(v); sig = _merge(sig, cs)
        decoded_cookies[dk] = dv
    body_type, body_parsed, body_flat, body_raw = _parse_body(ingress.raw_body, ingress.content_type)
    norm_body_flat = {}
    for k, v in body_flat.items():
        dk, _ = _full_norm(k)
        dv, bs = _full_norm(v); sig = _merge(sig, bs)
        norm_body_flat[dk] = dv
    for k, v in norm_body_flat.items():
        params.setdefault(k, []).append(v)
    all_inputs = " ".join([path, qs, body_raw[:4096],
        " ".join(f"{k}={v}" for k,v in decoded_headers.items()),
        " ".join(f"{k}={v}" for k,v in decoded_cookies.items())])
    return NormalisedRequest(
        ingress=ingress, decoded_path=path, decoded_query_string=qs,
        params=params, decoded_headers=decoded_headers, decoded_cookies=decoded_cookies,
        body_type=body_type, body_parsed=body_parsed, body_flat=norm_body_flat,
        body_raw_decoded=body_raw, all_inputs_combined=all_inputs,
        encoding_depth=sig["encoding_depth"], had_null_bytes=sig["had_null_bytes"],
        had_unicode_tricks=sig["had_unicode_tricks"], had_html_entities=sig["had_html_entities"],
        had_base64_payloads=sig["had_base64_payloads"],
    )
