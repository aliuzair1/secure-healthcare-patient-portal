# AI-WAF-IDS — Production-Grade Application Layer WAF with Embedded IDS

A modular, extensible Layer-7 Web Application Firewall with an embedded
Application Protocol-based IDS (APIDS). Designed for deployment behind NGINX.

---

## Architecture

```
NGINX (TLS termination, coarse rate limit)
        │
        ▼
┌─────────────────────────────────────────────┐
│              AI-WAF-IDS Pipeline            │
│                                             │
│  1. Ingress      (ingress.py)               │
│  2. Normalise    (normalizer.py)            │
│  3. Extract      (extractor.py)             │
│  4. Detect ──────────────────────────────┐ │
│     ├─ Rule Engine  (detection/rule_engine.py)   │
│     ├─ Behavioral   (detection/behavioral.py)    │
│     ├─ [ML Engine]  (detection/ml_interface.py)  │
│     └─ [Anomaly]    (detection/ml_interface.py)  │
│  5. Score        (scoring.py)              │
│  6. Decide       (decision.py)             │
│  7. Respond      (response.py)             │
│  8. Log          (logger.py)               │
└─────────────────────────────────────────────┘
        │
        ▼
   Flask Backend (your app)
```

---

## Quick Start

```bash
pip install -r requirements.txt

# Optional: set env vars
export WAF_ENV=production
export WAF_ADMIN_KEY=your-secret-key

python app.py          # development
gunicorn app:app -w 4  # production
```

---

## File Structure

```
waf/
├── app.py               ← Flask entry point + Admin API
├── config.py            ← All tuneable parameters
├── waf_engine.py        ← Pipeline orchestrator
├── ingress.py           ← Step 1: request ingestion + IP reputation
├── normalizer.py        ← Step 2: decode, de-obfuscate
├── extractor.py         ← Step 3: feature extraction (ML-ready)
├── scoring.py           ← Step 5: unified risk score
├── decision.py          ← Step 6: ALLOW/BLOCK/CHALLENGE/RATE_LIMIT
├── response.py          ← Step 7: HTTP response builder
├── logger.py            ← Step 8: structured JSON logging
├── detection/
│   ├── __init__.py      ← BaseDetector, DetectorRegistry, ThreatCategory
│   ├── rule_engine.py   ← 40+ OWASP signature rules
│   ├── behavioral.py    ← APIDS: session tracking, rate abuse, bot detection
│   └── ml_interface.py  ← ML/Anomaly stubs (sklearn, ONNX, REST)
├── rules/
│   ├── ip_blocklist.txt ← One IP/CIDR per line
│   └── ip_allowlist.txt
├── logs/                ← access.log, attack.log, error.log (JSON)
├── tests/test_waf.py    ← 36 unit tests (pytest)
└── nginx.conf           ← Production NGINX config
```

---

## OWASP Top 10 Coverage

| ID  | Category                        | Detection Method             |
|-----|---------------------------------|------------------------------|
| A01 | Broken Access Control           | Rules (BAC-001/002) + Session |
| A02 | Cryptographic Failures          | Rules (CRYPTO-001)           |
| A03 | Injection (SQLi/XSS/CMDi/XXE)  | Rules (SQLI/XSS/CMDI/XXE/SSTI/LDAPI) |
| A04 | Insecure Design                 | Behavioral patterns          |
| A05 | Security Misconfiguration       | Rules (MISCONFIG-001/002/003)|
| A06 | Vulnerable Components           | Path/UA probing rules        |
| A07 | Authentication Failures         | Rules + Behavioral brute-force|
| A08 | Data Integrity Failures         | Rules (CRLF/HTTP smuggling)  |
| A09 | Logging/Monitoring Failures     | Built-in structured logging  |
| A10 | SSRF                            | Rules (SSRF-001/002/003/004) |

---

## Integrating Your Flask Backend

**Option A — Single process (WAF + backend):**
```python
# In app.py, after creating `app`:
from your_backend.routes import blueprint
app.register_blueprint(blueprint, url_prefix="/api")
```

**Option B — WAF as WSGI middleware:**
```python
from app import app as waf_app
from your_backend.wsgi import backend_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

application = DispatcherMiddleware(waf_app, {"/api": backend_app})
```

---

## Plugging In an ML Model

1. Train a binary classifier on your feature vectors.
2. Serialise it (joblib for sklearn, ONNX for cross-framework).
3. In `config.py` (or environment variables):
   ```python
   config.enable_ml_engine = True
   config.ml.enabled       = True
   config.ml.model_type    = "sklearn"   # or "onnx" / "rest"
   config.ml.model_path    = "/models/waf_classifier.joblib"
   ```
4. No other code changes needed — the MLEngine is already registered.

---

## Admin API

All endpoints require header `X-WAF-Admin-Key: <config.admin_api_key>`.

| Method | Path                    | Action                        |
|--------|-------------------------|-------------------------------|
| GET    | /waf/health             | Liveness probe (no auth)      |
| GET    | /waf/admin/status       | Engine status                 |
| GET    | /waf/admin/ip/<ip>      | IP behavioural state          |
| POST   | /waf/admin/blocklist    | Block IP (body: {"ip":"..."}) |
| POST   | /waf/admin/allowlist    | Allow IP                      |
| POST   | /waf/admin/override     | Set path/IP policy override   |
| DELETE | /waf/admin/override     | Remove override               |
| GET    | /waf/admin/overrides    | List all overrides            |
| POST   | /waf/admin/reload       | Hot-reload IP lists           |

---

## Running Tests

```bash
python -m pytest tests/ -v
# 36 passed
```
