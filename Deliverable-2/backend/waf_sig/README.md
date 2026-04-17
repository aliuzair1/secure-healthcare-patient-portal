# Signature-Based WAF — Production-Grade Layer 7 Web Application Firewall

A clean, modular, signature-only WAF written in Python. No ML dependencies.
Sits behind NGINX and integrates with any Flask backend via a single
`before_request` hook.

---

## Architecture

```
NGINX (TLS · coarse rate-limit · IP forwarding)
         │
         ▼
┌────────────────────────────────────────┐
│           Signature WAF Pipeline        │
│                                        │
│  1. Ingress    → real-IP extraction    │
│                  IP allow/blocklist    │
│                                        │
│  2. Normalise  → URL decode (3-pass)   │
│                  HTML entity decode    │
│                  Unicode NFKC collapse  │
│                  Null-byte removal     │
│                  Base64 heuristic      │
│                  SQL comment stripping  │
│                                        │
│  3. Detect     → Rule Engine           │
│                  (40 regex signatures) │
│                                        │
│  4. Score      → unified [0.0–1.0]     │
│                  multi-match boost     │
│                  obfuscation boost     │
│                                        │
│  5. Decide     → BLOCK / CHALLENGE /   │
│                  RATE_LIMIT / LOG_ONLY │
│                  / ALLOW               │
│                                        │
│  6. Respond    → generic error body    │
│     + Log      → JSON access/attack    │
└────────────────────────────────────────┘
         │ None (allowed) or Response (blocked)
         ▼
   Your Flask Backend
```

---

## Quick Start

```bash
pip install -r requirements.txt

export WAF_ADMIN_KEY="your-secret-key"
export WAF_ENV="production"

# development
python app.py

# production (gunicorn)
gunicorn app:app -w 4 --bind 0.0.0.0:5000
```

---

## File Structure

```
waf_sig/
├── app.py               ← Flask entry point + Admin REST API
├── config.py            ← All tuneable parameters (thresholds, weights, paths)
├── waf_engine.py        ← Pipeline orchestrator (6-step flow)
├── ingress.py           ← Step 1: real-IP extraction, IP reputation
├── normalizer.py        ← Step 2: multi-pass decode + de-obfuscation
├── scoring.py           ← Step 4: unified risk score
├── decision.py          ← Step 5: ALLOW / BLOCK / CHALLENGE / RATE_LIMIT
├── response.py          ← Step 6: HTTP response builder
├── logger.py            ← Structured JSON rotating log files
├── detection/
│   ├── __init__.py      ← BaseDetector, DetectorRegistry, ThreatCategory
│   └── rule_engine.py   ← 40 WAF signature rules (OWASP Top 10 + extras)
├── rules/
│   ├── ip_blocklist.txt ← One IP or CIDR per line
│   └── ip_allowlist.txt
├── logs/                ← access.log, attack.log, error.log (JSON lines)
├── tests/test_waf.py    ← 51 tests (pytest) — all passing
└── nginx.conf           ← Production NGINX reverse-proxy config
```

---

## OWASP Top 10 Coverage

| ID   | Category                       | Rules                        |
|------|--------------------------------|------------------------------|
| A01  | Broken Access Control          | BAC-001, BAC-002             |
| A02  | Cryptographic Failures         | CRYPTO-001                   |
| A03  | Injection (SQL/XSS/CMDi/XXE)   | SQLI-001…010, XSS-001…008, CMDI-001…005, XXE-001…003, SSTI-001…003, LDAPI-001 |
| A04  | Insecure Design                | Structural normaliser signals |
| A05  | Security Misconfiguration      | MISCONFIG-001…003            |
| A06  | Vulnerable Components          | Scanner/tool UA patterns     |
| A07  | Authentication Failures        | BAC-002 (SQLi in auth)       |
| A08  | Data Integrity Failures        | CRLF-001                     |
| A09  | Logging/Monitoring             | Built-in structured logging  |
| A10  | SSRF                           | SSRF-001…004                 |
| +    | Supplementary                  | PT-001…004, OBF-001…003, BOT-001…002, REDIR-001 |

---

## Integrating Your Flask Backend

**Option A — Single process** (simplest, recommended for most cases):

```python
# In app.py, after `app = Flask(__name__)` and `waf = WAFEngine()`:
from your_backend.routes import blueprint
app.register_blueprint(blueprint, url_prefix="/api")

# The before_request WAF hook already protects every registered route.
# No other changes needed.
```

**Option B — Multiple blueprints**:

```python
from app import app
from users.routes import users_bp
from orders.routes import orders_bp
app.register_blueprint(users_bp,  url_prefix="/api/users")
app.register_blueprint(orders_bp, url_prefix="/api/orders")
```

**Option C — WSGI middleware** (WAF wraps a separate backend app):

```python
from app import app as waf_app
from your_backend.wsgi import backend_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

application = DispatcherMiddleware(waf_app, {"/api": backend_app})
```

---

## Tuning Thresholds

All thresholds are in `config.py` or environment variables:

```python
# config.py defaults
thresholds.block      = 0.75   # WAF_BLOCK_THRESHOLD
thresholds.challenge  = 0.50   # WAF_CHALLENGE_THRESHOLD
thresholds.rate_limit = 0.30   # WAF_RATE_LIMIT_THRESHOLD
thresholds.log_only   = 0.10
```

Run in `log_only` mode first (set `block=1.1`) to observe traffic before enabling enforcement.

---

## Admin API

All admin endpoints require the header `X-WAF-Admin-Key: <config.admin_api_key>`.

| Method  | Endpoint                        | Action                          |
|---------|---------------------------------|---------------------------------|
| GET     | `/waf/health`                   | Liveness probe (no auth)        |
| GET     | `/waf/admin/status`             | WAF config and engine info      |
| POST    | `/waf/admin/reload`             | Hot-reload IP lists from disk   |
| POST    | `/waf/admin/block-ip`           | Instantly block an IP           |
| DELETE  | `/waf/admin/block-ip`           | Remove an IP block              |
| POST    | `/waf/admin/allow-ip`           | Allowlist an IP                 |
| DELETE  | `/waf/admin/allow-ip`           | Remove from allowlist           |
| GET     | `/waf/admin/overrides`          | List all active overrides       |
| POST    | `/waf/admin/path-override`      | Set a path-level policy         |
| DELETE  | `/waf/admin/path-override`      | Remove a path-level policy      |
| GET     | `/waf/admin/rules`              | List all rules + enabled state  |
| PATCH   | `/waf/admin/rules/<rule_id>`    | Enable / disable a rule live    |

**Example — disable a noisy rule at runtime**:
```bash
curl -X PATCH http://localhost:5000/waf/admin/rules/BAC-001 \
     -H "X-WAF-Admin-Key: your-key" \
     -H "Content-Type: application/json" \
     -d '{"enabled": false}'
```

---

## IP Lists

Edit `rules/ip_blocklist.txt` and `rules/ip_allowlist.txt` (one IP or CIDR per line):

```
# ip_blocklist.txt
192.0.2.1
203.0.113.0/24
```

Then hot-reload without restart:
```bash
curl -X POST http://localhost:5000/waf/admin/reload \
     -H "X-WAF-Admin-Key: your-key"
```

---

## Running Tests

```bash
python -m pytest tests/ -v
# 51 passed
```

---

## Adding a New Rule

Open `detection/rule_engine.py` and append to `RULES`:

```python
WAFRule(
    rule_id="MYAPP-001",
    description="Custom: block requests with X-Internal header",
    category=ThreatCategory.A01_BROKEN_ACCESS_CONTROL,
    apply_to=["headers"],
    pattern=r"x-internal:\s*true",
    score=0.80,
),
```

That is the complete change. Restart (or implement hot-reload via admin API) to activate.

---

## Log Format

Every line in `logs/attack.log` is a complete JSON object:

```json
{
  "timestamp": "2025-03-15T10:23:45.123+00:00",
  "level": "WARNING",
  "event_type": "attack",
  "request_id": "abc123",
  "client_ip": "1.2.3.4",
  "method": "GET",
  "path": "/search",
  "query": "id=1 UNION SELECT password FROM users",
  "action": "BLOCK",
  "reason": "Score 0.950 >= block threshold 0.75",
  "risk_score": 0.95,
  "risk_label": "CRITICAL",
  "matched_categories": ["A03:SQLInjection"],
  "rule_ids": ["SQLI-001"],
  "top_findings": [
    {"rule_id": "SQLI-001", "category": "A03:SQLInjection", "score": 0.95,
     "details": "UNION-based SQL injection [field: all_inputs]"}
  ],
  "obfuscation_detected": false,
  "duration_ms": 0.8
}
```

Ship to ELK / Splunk with Filebeat tailing `logs/attack.log`.
