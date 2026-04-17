"""
normalizer.py — Request Normalisation Layer (Pipeline Step 2)

Attackers encode payloads to bypass pattern matching.  This module
produces a canonical decoded form that the rule engine pattern-matches
against, catching:

  • Double / triple URL-encoding  (%2527 → %27 → ')
  • HTML entity encoding          (&lt;script&gt; → <script>)
  • Unicode full-width chars      ／ → /
  • Null bytes                    %00 → removed
  • Base64-embedded payloads      dW5pb24gc2VsZWN0 → union select
  • SQL inline comment stripping  UN/**/ION → UNION

Each normalisation technique is flagged as a signal so the scoring
engine can apply an obfuscation multiplier when needed.

Output: NormalisedRequest — a decoded view of the request that every
downstream module works with exclusively.
"""

from __future__ import annotations

import base64
import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote_plus

from ingress import IngressRequest
from logger import get_logger

logger = get_logger("normalizer")

_MAX_DECODE_PASSES = 3
_MAX_BODY_BYTES    = 1 * 1024 * 1024   # 1 MB — inspect limit


# ---------------------------------------------------------------------------
# NormalisedRequest — decoded view of an IngressRequest
# ---------------------------------------------------------------------------

@dataclass
class NormalisedRequest:
    ingress:              IngressRequest

    decoded_path:         str  = ""
    decoded_query_string: str  = ""

    # Combined decoded string for single-pass rule scanning
    all_inputs:           str  = ""

    # Flat decoded parameter map  (query + body merged)
    params:               Dict[str, List[str]] = field(default_factory=dict)

    # Decoded headers (lower-case keys) and cookies
    decoded_headers:      Dict[str, str] = field(default_factory=dict)
    decoded_cookies:      Dict[str, str] = field(default_factory=dict)

    # Body
    body_type:            str  = "empty"    # json | form | xml | raw | empty
    body_parsed:          Any  = None
    body_flat:            Dict[str, str] = field(default_factory=dict)
    body_raw_decoded:     str  = ""

    # Obfuscation signals (used by scoring engine)
    encoding_depth:       int  = 0
    had_null_bytes:       bool = False
    had_html_entities:    bool = False
    had_unicode_tricks:   bool = False
    had_base64_payloads:  bool = False


# ---------------------------------------------------------------------------
# Decode helpers
# ---------------------------------------------------------------------------

_NULL_RE       = re.compile(r"\x00+")
_HTML_ENT_RE   = re.compile(r"&[a-zA-Z]{2,8};|&#\d{1,6};|&#x[0-9a-fA-F]{1,6};")
_BASE64_RE     = re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")  # 32-char minimum avoids false positives on URL paths
_SQL_COMMENT   = re.compile(r"/\*.*?\*/", re.DOTALL)

# Full-width → ASCII collapse table
_FW_TABLE = str.maketrans(
    "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ"
    "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ"
    "０１２３４５６７８９",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789",
)


def _url_decode(s: str):
    depth = 0
    for _ in range(_MAX_DECODE_PASSES):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
        depth += 1
    return s, depth


def _normalise_value(s: str) -> tuple[str, dict]:
    """Apply the full normalisation chain to a single string value."""
    sig = dict(encoding_depth=0, had_null_bytes=False,
               had_html_entities=False, had_unicode_tricks=False,
               had_base64_payloads=False)

    # 1. URL-decode (iterative)
    s, depth = _url_decode(s)
    sig["encoding_depth"] = depth

    # 2. HTML entity decode
    if _HTML_ENT_RE.search(s):
        s = html.unescape(s)
        sig["had_html_entities"] = True

    # 3. Null bytes
    cleaned = _NULL_RE.sub("", s)
    if cleaned != s:
        sig["had_null_bytes"] = True
    s = cleaned

    # 4. Unicode NFKC + full-width collapse
    normalised = unicodedata.normalize("NFKC", s).translate(_FW_TABLE)
    if normalised != s:
        sig["had_unicode_tricks"] = True
    s = normalised

    # 5. Base64 heuristic decode
    def _try_decode(m: re.Match) -> str:
        blob = m.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
            if any(c.isalpha() for c in decoded):
                sig["had_base64_payloads"] = True
                return decoded
        except Exception:
            pass
        return blob
    s = _BASE64_RE.sub(_try_decode, s)

    # 6. Strip SQL inline comments  (/**/ evasion)
    s = _SQL_COMMENT.sub(" ", s)

    return s, sig


def _merge(a: dict, b: dict) -> dict:
    return {
        "encoding_depth":     max(a["encoding_depth"], b["encoding_depth"]),
        "had_null_bytes":     a["had_null_bytes"]     or b["had_null_bytes"],
        "had_html_entities":  a["had_html_entities"]  or b["had_html_entities"],
        "had_unicode_tricks": a["had_unicode_tricks"]  or b["had_unicode_tricks"],
        "had_base64_payloads":a["had_base64_payloads"] or b["had_base64_payloads"],
    }


def _blank() -> dict:
    return dict(encoding_depth=0, had_null_bytes=False,
                had_html_entities=False, had_unicode_tricks=False,
                had_base64_payloads=False)


# ---------------------------------------------------------------------------
# Body parser
# ---------------------------------------------------------------------------

def _parse_body(raw: bytes, content_type: str):
    if not raw:
        return "empty", None, {}, ""
    raw_str = raw[:_MAX_BODY_BYTES].decode("utf-8", errors="replace")
    ct = content_type.lower().split(";")[0].strip()

    if "json" in ct or raw_str.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(raw_str)
            return "json", parsed, _flatten_json(parsed), raw_str
        except (json.JSONDecodeError, ValueError):
            pass

    if "form" in ct or "x-www-form-urlencoded" in ct:
        try:
            parsed = parse_qs(raw_str, keep_blank_values=True)
            flat = {k: " ".join(v) for k, v in parsed.items()}
            return "form", parsed, flat, raw_str
        except Exception:
            pass

    if "xml" in ct:
        return "xml", None, {"__xml": raw_str}, raw_str

    if "multipart" in ct:
        return "multipart", None, {"__multipart": raw_str[:2048]}, raw_str

    return "raw", None, {"__raw": raw_str}, raw_str


def _flatten_json(obj: Any, prefix: str = "", depth: int = 0) -> dict:
    out: dict = {}
    if depth > 8:
        out[prefix] = str(obj)
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten_json(v, f"{prefix}.{k}" if prefix else k, depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            out.update(_flatten_json(v, f"{prefix}[{i}]", depth + 1))
    else:
        out[prefix] = str(obj)
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def normalise(ingress: IngressRequest) -> NormalisedRequest:
    """Decode and canonicalise an IngressRequest into a NormalisedRequest."""
    sig = _blank()

    # Path
    path, ps = _normalise_value(ingress.path)
    sig = _merge(sig, ps)

    # Query string
    qs, qs_s = _normalise_value(ingress.query_string)
    sig = _merge(sig, qs_s)

    # Query parameters
    params: Dict[str, List[str]] = {}
    for k, values in ingress.query_params.items():
        dk, _ = _normalise_value(k)
        decoded_vals = []
        for v in values:
            dv, vs = _normalise_value(v)
            sig = _merge(sig, vs)
            decoded_vals.append(dv)
        params[dk] = decoded_vals

    # Headers — skip Authorization to prevent JWT Bearer tokens from being
    # decoded (base64 heuristic) and injected into all_inputs, which causes
    # false-positive SQL injection / XSS rule matches on every auth'd request.
    _SKIP_HEADERS = {"authorization", "cookie"}
    decoded_headers: Dict[str, str] = {}
    headers_for_scan: Dict[str, str] = {}
    for k, v in ingress.headers.items():
        lk = k.lower().strip()
        if lk in _SKIP_HEADERS:
            # Store as-is without normalising — we still want to access value
            # (e.g. for logging) but NOT decode JWT as base64 or scan it.
            decoded_headers[lk] = v
            continue
        dv, hs = _normalise_value(v)
        sig = _merge(sig, hs)
        decoded_headers[lk] = dv
        headers_for_scan[lk] = dv

    # Cookies
    decoded_cookies: Dict[str, str] = {}
    for k, v in ingress.cookies.items():
        dk, _ = _normalise_value(k)
        dv, cs = _normalise_value(v)
        sig = _merge(sig, cs)
        decoded_cookies[dk] = dv

    # Body
    body_type, body_parsed, body_flat, body_raw_str = _parse_body(
        ingress.raw_body, ingress.content_type
    )
    norm_body_flat: Dict[str, str] = {}
    for k, v in body_flat.items():
        dk, _ = _normalise_value(k)
        dv, bs = _normalise_value(v)
        sig = _merge(sig, bs)
        norm_body_flat[dk] = dv

    # Merge body params into unified param map
    for k, v in norm_body_flat.items():
        params.setdefault(k, []).append(v)

    # Combined string for single-pass rule scanning
    # Use headers_for_scan (excludes Authorization/Cookie) to avoid false positives
    all_inputs = " ".join([
        path,
        qs,
        body_raw_str[:4096],
        " ".join(f"{k}={v}" for k, v in headers_for_scan.items()),
        " ".join(f"{k}={v}" for k, v in decoded_cookies.items()),
    ])

    nr = NormalisedRequest(
        ingress              = ingress,
        decoded_path         = path,
        decoded_query_string = qs,
        all_inputs           = all_inputs,
        params               = params,
        decoded_headers      = decoded_headers,
        decoded_cookies      = decoded_cookies,
        body_type            = body_type,
        body_parsed          = body_parsed,
        body_flat            = norm_body_flat,
        body_raw_decoded     = body_raw_str,
        encoding_depth       = sig["encoding_depth"],
        had_null_bytes       = sig["had_null_bytes"],
        had_html_entities    = sig["had_html_entities"],
        had_unicode_tricks   = sig["had_unicode_tricks"],
        had_base64_payloads  = sig["had_base64_payloads"],
    )

    if sig["encoding_depth"] > 1 or sig["had_null_bytes"] or sig["had_unicode_tricks"]:
        logger.warning(
            "Obfuscation in %s: depth=%d nulls=%s unicode=%s b64=%s",
            ingress.request_id[:8],
            sig["encoding_depth"],
            sig["had_null_bytes"],
            sig["had_unicode_tricks"],
            sig["had_base64_payloads"],
        )
    return nr
