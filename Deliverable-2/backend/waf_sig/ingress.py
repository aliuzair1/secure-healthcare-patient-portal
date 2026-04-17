"""
ingress.py — Ingress Layer (Pipeline Step 1)

Responsibilities:
  - Build a framework-agnostic IngressRequest from a Flask Request.
  - Extract the real client IP from NGINX-forwarded headers.
  - Evaluate IP allowlist / blocklist before any expensive processing.

The IngressRequest dataclass is the *only* object that flows through the
rest of the pipeline; no downstream module ever imports Flask.
"""

from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List

from flask import Request

from config import config
from logger import get_logger

logger = get_logger("ingress")


# ---------------------------------------------------------------------------
# Canonical request snapshot  —  immutable; all downstream modules read this
# ---------------------------------------------------------------------------

@dataclass
class IngressRequest:
    request_id:     str
    timestamp:      float
    client_ip:      str
    real_ip_source: str              # which header supplied the real IP

    method:         str
    path:           str
    query_string:   str
    http_version:   str
    scheme:         str

    headers:        Dict[str, str]
    query_params:   Dict[str, List[str]]
    cookies:        Dict[str, str]

    raw_body:       bytes
    content_type:   str
    content_length: int

    user_agent:     str
    referer:        str
    host:           str

    ip_allowlisted: bool = False
    ip_blocklisted: bool = False


# ---------------------------------------------------------------------------
# IP list loader  —  called once at startup and again on admin /reload
# ---------------------------------------------------------------------------

_ALLOWLIST:          set  = set()
_BLOCKLIST:          set  = set()
_ALLOWLIST_NETWORKS: list = []
_BLOCKLIST_NETWORKS: list = []


def _load_list(filepath: str):
    exact, networks = set(), []
    if not filepath or not os.path.exists(filepath):
        return exact, networks
    try:
        with open(filepath) as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "/" in line:
                    try:
                        networks.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        logger.warning("Invalid CIDR in list: %s", line)
                else:
                    exact.add(line)
    except OSError as exc:
        logger.error("Cannot read IP list %s: %s", filepath, exc)
    return exact, networks


def reload_ip_lists() -> None:
    """Hot-reload allowlist and blocklist from disk. Thread-safe (GIL-protected swap)."""
    global _ALLOWLIST, _ALLOWLIST_NETWORKS, _BLOCKLIST, _BLOCKLIST_NETWORKS
    _ALLOWLIST, _ALLOWLIST_NETWORKS = _load_list(config.reputation.allowlist_file)
    _BLOCKLIST, _BLOCKLIST_NETWORKS = _load_list(config.reputation.blocklist_file)
    logger.info(
        "IP lists loaded — allow: %d entries, block: %d entries",
        len(_ALLOWLIST) + len(_ALLOWLIST_NETWORKS),
        len(_BLOCKLIST) + len(_BLOCKLIST_NETWORKS),
    )


def _ip_in(ip_str: str, exact: set, networks: list) -> bool:
    if ip_str in exact:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in networks)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Trusted proxy CIDRs  (RFC-1918 + loopback)
# ---------------------------------------------------------------------------

_TRUSTED_PROXIES = [
    ipaddress.ip_network(n) for n in [
        "127.0.0.0/8", "10.0.0.0/8",
        "172.16.0.0/12", "192.168.0.0/16", "::1/128",
    ]
]


def _is_trusted_proxy(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _TRUSTED_PROXIES)
    except ValueError:
        return False


def _is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Real-IP extraction
# ---------------------------------------------------------------------------

def _real_ip(flask_req: Request):
    """Return (ip, source_header).  Priority: X-Real-IP → X-Forwarded-For → REMOTE_ADDR."""
    x_real = flask_req.headers.get("X-Real-IP", "").strip()
    if x_real and _is_valid_ip(x_real):
        return x_real, "X-Real-IP"

    xff = flask_req.headers.get("X-Forwarded-For", "")
    if xff:
        for candidate in (c.strip() for c in xff.split(",")):
            if _is_valid_ip(candidate) and not _is_trusted_proxy(candidate):
                return candidate, "X-Forwarded-For"

    return flask_req.remote_addr or "0.0.0.0", "REMOTE_ADDR"


# ---------------------------------------------------------------------------
# Public factory  —  the only place the pipeline touches Flask's Request
# ---------------------------------------------------------------------------

def build_ingress_request(flask_req: Request, request_id: str) -> IngressRequest:
    """
    Convert a Flask Request into a framework-agnostic IngressRequest.
    Never raises — all errors produce safe defaults.
    """
    client_ip, ip_source = _real_ip(flask_req)

    try:
        raw_body = flask_req.get_data(cache=True) or b""
    except Exception:
        raw_body = b""

    req = IngressRequest(
        request_id     = request_id,
        timestamp      = time.time(),
        client_ip      = client_ip,
        real_ip_source = ip_source,
        method         = flask_req.method.upper(),
        path           = flask_req.path,
        query_string   = flask_req.query_string.decode("utf-8", errors="replace"),
        http_version   = flask_req.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        scheme         = flask_req.scheme,
        headers        = {k: v for k, v in flask_req.headers},
        query_params   = {k: flask_req.args.getlist(k) for k in flask_req.args},
        cookies        = dict(flask_req.cookies),
        raw_body       = raw_body,
        content_type   = flask_req.content_type or "",
        content_length = flask_req.content_length or len(raw_body),
        user_agent     = flask_req.headers.get("User-Agent", ""),
        referer        = flask_req.headers.get("Referer", ""),
        host           = flask_req.host or "",
    )
    req.ip_allowlisted = _ip_in(client_ip, _ALLOWLIST, _ALLOWLIST_NETWORKS)
    req.ip_blocklisted = _ip_in(client_ip, _BLOCKLIST, _BLOCKLIST_NETWORKS)
    return req


# Load lists on first import
reload_ip_lists()
