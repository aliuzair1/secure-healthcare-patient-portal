"""ingress.py — Ingress Layer (Pipeline Step 1)"""
from __future__ import annotations
import ipaddress, os, time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from flask import Request
from config import config
from logger import get_logger
logger = get_logger("ingress")

@dataclass
class IngressRequest:
    request_id: str
    timestamp: float
    client_ip: str
    real_ip_source: str
    method: str
    path: str
    query_string: str
    http_version: str
    scheme: str
    headers: Dict[str, str]
    query_params: Dict[str, List[str]]
    cookies: Dict[str, str]
    raw_body: bytes
    content_type: str
    content_length: int
    user_agent: str
    referer: str
    host: str
    ip_allowlisted: bool = False
    ip_blocklisted: bool = False
    is_trusted_proxy: bool = False

_ALLOWLIST: set = set()
_BLOCKLIST: set = set()
_ALLOWLIST_NETWORKS: list = []
_BLOCKLIST_NETWORKS: list = []

def _load_ip_list(filepath):
    exact, networks = set(), []
    if not filepath or not os.path.exists(filepath):
        return exact, networks
    try:
        for line in open(filepath):
            line = line.strip()
            if not line or line.startswith("#"): continue
            if "/" in line:
                try: networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError: pass
            else:
                exact.add(line)
    except OSError: pass
    return exact, networks

def reload_ip_lists():
    global _ALLOWLIST,_ALLOWLIST_NETWORKS,_BLOCKLIST,_BLOCKLIST_NETWORKS
    _ALLOWLIST,_ALLOWLIST_NETWORKS = _load_ip_list(config.reputation.allowlist_file)
    _BLOCKLIST,_BLOCKLIST_NETWORKS = _load_ip_list(config.reputation.blocklist_file)
    logger.info("IP lists loaded — allow:%d block:%d",
                len(_ALLOWLIST)+len(_ALLOWLIST_NETWORKS),
                len(_BLOCKLIST)+len(_BLOCKLIST_NETWORKS))

_TRUSTED_PROXIES = [ipaddress.ip_network(n) for n in
    ["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","::1/128"]]

def _is_trusted_proxy(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _TRUSTED_PROXIES)
    except ValueError: return False

def _is_valid_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def _ip_in_list(ip, exact, networks):
    if ip in exact: return True
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in networks)
    except ValueError: return False

def _extract_real_ip(flask_req):
    x_real = flask_req.headers.get("X-Real-IP","").strip()
    if x_real and _is_valid_ip(x_real): return x_real, "X-Real-IP"
    xff = flask_req.headers.get("X-Forwarded-For","")
    if xff:
        for c in [ip.strip() for ip in xff.split(",")]:
            if _is_valid_ip(c) and not _is_trusted_proxy(c): return c, "X-Forwarded-For"
    return flask_req.remote_addr or "0.0.0.0", "REMOTE_ADDR"

def build_ingress_request(flask_req: Request, request_id: str) -> IngressRequest:
    client_ip, ip_source = _extract_real_ip(flask_req)
    try: raw_body = flask_req.get_data(cache=True) or b""
    except Exception: raw_body = b""
    req = IngressRequest(
        request_id=request_id, timestamp=time.time(),
        client_ip=client_ip, real_ip_source=ip_source,
        method=flask_req.method.upper(), path=flask_req.path,
        query_string=flask_req.query_string.decode("utf-8","replace"),
        http_version=flask_req.environ.get("SERVER_PROTOCOL","HTTP/1.1"),
        scheme=flask_req.scheme,
        headers={k: v for k, v in flask_req.headers},
        query_params={k: flask_req.args.getlist(k) for k in flask_req.args},
        cookies=dict(flask_req.cookies), raw_body=raw_body,
        content_type=flask_req.content_type or "",
        content_length=flask_req.content_length or len(raw_body),
        user_agent=flask_req.headers.get("User-Agent",""),
        referer=flask_req.headers.get("Referer",""),
        host=flask_req.host or "",
        is_trusted_proxy=_is_trusted_proxy(client_ip),
    )
    req.ip_allowlisted = _ip_in_list(client_ip, _ALLOWLIST, _ALLOWLIST_NETWORKS)
    req.ip_blocklisted = _ip_in_list(client_ip, _BLOCKLIST, _BLOCKLIST_NETWORKS)
    return req

reload_ip_lists()
