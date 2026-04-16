"""detection/behavioral.py — Behavioral / APIDS Engine"""
from __future__ import annotations
import math, re, threading, time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set
from config import config
from detection import BaseDetector, DetectionResult, ThreatCategory
from logger import get_logger
logger = get_logger("behavioral")
cfg = config.behavioral; rl_cfg = config.rate_limit

@dataclass
class _IPState:
    request_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=10_000))
    failed_auth_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    path_404_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    distinct_paths: Set[str] = field(default_factory=set)
    distinct_usernames: Set[str] = field(default_factory=set)
    user_agents: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)

@dataclass
class _SessionState:
    session_id: str
    start_time: float = field(default_factory=time.time)
    last_request_time: float = field(default_factory=time.time)
    request_count: int = 0
    path_history: Deque[str] = field(default_factory=lambda: deque(maxlen=200))
    method_history: Deque[str] = field(default_factory=lambda: deque(maxlen=200))
    param_keys_seen: Set[str] = field(default_factory=set)
    prev_param_key_snapshot: Set[str] = field(default_factory=set)
    accessed_admin: bool = False

_lock = threading.Lock()
_ip_store: Dict[str, _IPState] = {}
_session_store: Dict[str, _SessionState] = {}

_ADMIN_RE = re.compile(r"/(admin|administrator|superuser|root|config|settings|system|management|console)", re.IGNORECASE)
_AUTH_RE = re.compile(r"/(login|signin|auth|token|oauth|api/auth|api/login)", re.IGNORECASE)
_SESSION_COOKIES = frozenset(["session","sessionid","session_id","jsessionid","phpsessid","asp.net_sessionid","connect.sid","sid"])

def _get_session_id(nr):
    for name in _SESSION_COOKIES:
        if name in nr.decoded_cookies: return nr.decoded_cookies[name][:128]
    auth = nr.decoded_headers.get("authorization","")
    if auth.lower().startswith("bearer "): return "jwt:" + auth[7:71]
    return None

def _evict_stale(now):
    stale_s = [s for s,ss in _session_store.items() if now - ss.last_request_time > cfg.session_ttl_seconds]
    for s in stale_s: del _session_store[s]
    stale_i = [ip for ip,st in _ip_store.items() if now - st.last_seen > rl_cfg.window_seconds * 10]
    for ip in stale_i: del _ip_store[ip]

def _list_entropy(items):
    if not items: return 0.0
    from collections import Counter
    c = Counter(items); t = len(items)
    return -sum((v/t)*math.log2(v/t) for v in c.values())

class BehavioralEngine(BaseDetector):
    name = "behavioral_engine"
    _evict_counter = 0; _EVICT_EVERY = 500

    def detect(self, nr, fv):
        results = []; now = time.time(); ip = nr.ingress.client_ip
        with _lock:
            self._evict_counter += 1
            if self._evict_counter >= self._EVICT_EVERY:
                _evict_stale(now); self._evict_counter = 0
            if ip not in _ip_store: _ip_store[ip] = _IPState(first_seen=now, last_seen=now)
            st = _ip_store[ip]; st.last_seen = now
            st.request_timestamps.append(now); st.distinct_paths.add(nr.decoded_path)
            ua = nr.ingress.user_agent
            if ua and (not st.user_agents or st.user_agents[-1] != ua): st.user_agents.append(ua)
            sid = _get_session_id(nr); ss = None
            if sid:
                if sid not in _session_store: _session_store[sid] = _SessionState(session_id=sid)
                ss = _session_store[sid]; ss.request_count += 1; ss.last_request_time = now
                ss.path_history.append(nr.decoded_path); ss.method_history.append(nr.ingress.method)
                ss.param_keys_seen.update(nr.params.keys())
                if _ADMIN_RE.search(nr.decoded_path): ss.accessed_admin = True
            window_start = now - rl_cfg.window_seconds
            recent_reqs = sum(1 for t in st.request_timestamps if t >= window_start)
            fv.session_request_count = ss.request_count if ss else 0
            fv.session_age_seconds = (now - ss.start_time) if ss else 0.0
            fv.ip_request_rate = recent_reqs / rl_cfg.window_seconds
            fv.distinct_paths_count = len(st.distinct_paths)

        # Checks (outside lock)
        results += self._check_rate(ip, st, recent_reqs)
        results += self._check_path_scan(ip, st, now)
        results += self._check_cred_stuffing(ip, st, nr, now)
        results += self._check_ua_cycling(ip, st)
        results += self._check_api_abuse(ip, fv.ip_request_rate)
        results += self._check_obfuscation(nr, fv)
        if ss: results += self._check_session(ss, nr, now)
        return results

    def _check_rate(self, ip, st, recent):
        if recent > rl_cfg.max_requests * rl_cfg.burst_multiplier:
            return [DetectionResult(0.85,True,ThreatCategory.RATE_ABUSE,"RATE-001",
                f"IP {ip} sent {recent} requests in {rl_cfg.window_seconds}s (burst)",
                {"ip":ip,"count":recent})]
        if recent > rl_cfg.max_requests:
            return [DetectionResult(0.65,True,ThreatCategory.RATE_ABUSE,"RATE-002",
                f"IP {ip} sent {recent} requests in {rl_cfg.window_seconds}s",{"ip":ip,"count":recent})]
        return []

    def _check_path_scan(self, ip, st, now):
        r = []
        ws = now - rl_cfg.window_seconds
        f404 = sum(1 for t in st.path_404_timestamps if t >= ws)
        if f404 >= cfg.max_404_per_window:
            r.append(DetectionResult(0.80,True,ThreatCategory.BOT_TRAFFIC,"SCAN-001",
                f"IP {ip} triggered {f404} 404s — path scan",{"ip":ip,"404_count":f404}))
        if len(st.distinct_paths) > 200:
            r.append(DetectionResult(0.75,True,ThreatCategory.BOT_TRAFFIC,"SCAN-002",
                f"IP {ip} accessed {len(st.distinct_paths)} distinct paths — enumeration",
                {"ip":ip,"distinct_paths":len(st.distinct_paths)}))
        return r

    def _check_cred_stuffing(self, ip, st, nr, now):
        r = []
        if not _AUTH_RE.search(nr.decoded_path): return r
        for fn in ("username","email","user","login","identifier"):
            for v in nr.params.get(fn, []): st.distinct_usernames.add(v.lower().strip())
        if len(st.distinct_usernames) >= cfg.credential_stuffing_threshold:
            r.append(DetectionResult(0.90,True,ThreatCategory.CREDENTIAL_STUFFING,"CRED-001",
                f"IP {ip} tried {len(st.distinct_usernames)} distinct usernames — credential stuffing",
                {"ip":ip,"distinct_users":len(st.distinct_usernames)}))
        ws = now - cfg.failed_auth_window
        fails = sum(1 for t in st.failed_auth_timestamps if t >= ws)
        if fails >= cfg.max_failed_auth:
            r.append(DetectionResult(0.85,True,ThreatCategory.A07_AUTH_FAILURE,"AUTH-BF-001",
                f"IP {ip} had {fails} auth failures in {cfg.failed_auth_window}s",
                {"ip":ip,"failed_auth_count":fails}))
        return r

    def _check_ua_cycling(self, ip, st):
        if len(st.user_agents) >= 5 and _list_entropy(st.user_agents[-20:]) > 3.0:
            return [DetectionResult(0.70,True,ThreatCategory.BOT_TRAFFIC,"BOT-UA-001",
                f"IP {ip} cycling user-agents — bot farm indicator",
                {"ip":ip,"ua_count":len(st.user_agents)})]
        return []

    def _check_api_abuse(self, ip, rps):
        if rps >= cfg.api_abuse_rps:
            return [DetectionResult(0.80,True,ThreatCategory.API_ABUSE,"API-001",
                f"IP {ip} sending {rps:.1f} req/s — API abuse",{"ip":ip,"rps":rps})]
        return []

    def _check_session(self, ss, nr, now):
        r = []; age = now - ss.start_time
        new_keys = ss.param_keys_seen - ss.prev_param_key_snapshot
        ss.prev_param_key_snapshot = set(ss.param_keys_seen)
        if len(new_keys) > 30 and age < 60:
            r.append(DetectionResult(0.65,True,ThreatCategory.BOT_TRAFFIC,"SESSION-001",
                f"Session introduced {len(new_keys)} new param keys in {age:.0f}s",
                {"new_keys":len(new_keys),"session_age":age}))
        if ss.accessed_admin and age < 5:
            r.append(DetectionResult(0.70,True,ThreatCategory.A01_BROKEN_ACCESS_CONTROL,"SESSION-002",
                f"Admin endpoint accessed within {age:.1f}s of session start",{"session_age":age}))
        return r

    def _check_obfuscation(self, nr, fv):
        flags = sum([fv.encoding_depth > 1, fv.had_html_entities, fv.had_unicode_tricks,
                     fv.had_base64_payloads, fv.had_null_bytes])
        if flags >= 2:
            return [DetectionResult(0.75,True,ThreatCategory.PAYLOAD_OBFUSCATION,"OBF-BEH-001",
                f"Multi-layer obfuscation ({flags} techniques)",
                {"encoding_depth":fv.encoding_depth,"html_entities":fv.had_html_entities,
                 "unicode":fv.had_unicode_tricks,"base64":fv.had_base64_payloads,"null_bytes":fv.had_null_bytes})]
        return []

def record_404(client_ip):
    with _lock:
        if client_ip not in _ip_store: _ip_store[client_ip] = _IPState()
        _ip_store[client_ip].path_404_timestamps.append(time.time())

def record_auth_failure(client_ip):
    with _lock:
        if client_ip not in _ip_store: _ip_store[client_ip] = _IPState()
        _ip_store[client_ip].failed_auth_timestamps.append(time.time())

def get_ip_stats(client_ip):
    with _lock:
        st = _ip_store.get(client_ip)
        if not st: return {}
        now = time.time(); ws = now - rl_cfg.window_seconds
        return {"ip":client_ip,
                "recent_requests":sum(1 for t in st.request_timestamps if t >= ws),
                "distinct_paths":len(st.distinct_paths),
                "distinct_users":len(st.distinct_usernames),
                "ua_count":len(set(st.user_agents)),
                "first_seen":st.first_seen,"last_seen":st.last_seen}
