# Secure Healthcare Patient Portal

This directory contains the production codebase for the Secure Healthcare Patient Portal, a full-stack healthcare web application designed with a strong emphasis on cybersecurity, privacy, and compliance with industry best practices.

**Live Application:** [secure-healthcare-patient-portal.vercel.app](https://secure-healthcare-patient-portal.vercel.app)

---

## Overview

The Secure Healthcare Patient Portal enables patients and healthcare staff to manage and interact with sensitive medical data securely. The application architecture and implementation are centered on defense-in-depth, robust authentication, and data integrity controls to mitigate real-world threats in medical and regulated environments.

- **Frontend:** JavaScript (React/Next.js), deployed on [Vercel](https://vercel.com/)
- **Backend:** Python (Flask/FastAPI as applicable), deployed on [Render](https://render.com/)
- **Database:** [Supabase](https://supabase.com/) (PostgreSQL, managed), with enforced security rules

---

## Security Architecture

Security has been integrated at every layer of the application:

### Custom Web Application Firewall (WAF)

A purpose-built Web Application Firewall (WAF) is implemented at the application layer of the backend API service. Its features include:

- **Centralized Request Interception:** All incoming HTTP requests are inspected before processing.
- **Input Validation:** Proactive filtering and sanitization to block SQL Injection (SQLi), Cross-Site Scripting (XSS), and other code injection attacks.
- **CSRF Protection:** All state-changing requests require validated custom anti-CSRF tokens and strict origin/referer checking.
- **Rate Limiting:** Brute-force attacks and credential stuffing attempts are detected and throttled.
- **Anomaly Detection:** The WAF monitors traffic patterns and triggers security events when anomalies are observed.
- **Structured Logging:** All denied or suspicious requests are logged with relevant metadata for incident response and audit.

#### Example WAF Rule Logic

```python
def waf_middleware(request):
    if has_sql_injection(request.data):
        log_event(type="blocked_sql_injection", user_ip=request.ip)
        return deny_request("Blocked: SQL Injection detected.")
    if has_xss_payload(request.data):
        log_event(type="blocked_xss", user_ip=request.ip)
        return deny_request("Blocked: XSS attempt detected.")
    if exceeded_rate_limit(request):
        log_event(type="rate_limit", user_ip=request.ip)
        return deny_request("Blocked: Rate limit exceeded.")
# ... additional context-aware checks
```

### Additional Security Measures

- **End-to-End Encryption:** All communications between client, backend, and database are enforced over HTTPS/TLS. Sensitive data at rest is encrypted in the database.
- **Authentication & Authorization:**
  - Passwords are hashed using a strong algorithm (bcrypt/argon2) and not stored in plaintext.
  - JWT-based authentication with strict expiration, integrity checking, and role-based access (RBAC) controls.
- **Frontend Security:**
  - Content Security Policy (CSP) prevents unauthorized script execution.
  - React/Next.js output encoding further reduces XSS risk.
  - Client input is validated before submission.
- **Logging & Auditing:**
  - Security-relevant user actions, authentication events, data change operations, and failed access attempts are audited with immutable logs.
- **Secure Software Development Lifecycle (SSDLC):**
  - Adheres to modern secure coding practices including dependency management (dependabot, pip audit, npm audit) and code reviews.

---

## Application Architecture

- **Frontend (Vercel):**
  - Built using React/Next.js for speed, scalability, and modern UX.
  - Deployed globally via [Vercel](https://secure-healthcare-patient-portal.vercel.app) for minimal latency and instant rollbacks.
  - Secure environmental variable management.

- **Backend (Render):**
  - Python RESTful API with Flask/FastAPI.
  - Custom WAF runs as middleware for all endpoints.
  - Backend services are securely isolated and expose only public API endpoints.
  - Deployment and scaling managed by [Render](https://render.com/).

- **Database (Supabase):**
  - PostgreSQL used with strict Row Level Security (RLS) rules.
  - Supabase authentication and authorization features are combined with application-level controls.
  - Regular backups and automated threat detection.

---

## How to Run Locally

1. **Clone the repository:**
    ```bash
    git clone https://github.com/aliuzair1/secure-healthcare-patient-portal.git
    cd secure-healthcare-patient-portal/deliverables-2
    ```

2. **Backend Setup:**
    - Create and activate a Python virtual environment
    - Install dependencies
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
    - Configure `.env` with secure secrets (see `.env.example` if available)
    - Run backend server
    ```bash
    python app.py
    ```

3. **Frontend Setup:**
    ```bash
    cd frontend
    npm install
    npm run dev
    ```

4. **Database:**
    - Requires connection credentials for Supabase PostgreSQL (see environment configuration)

---

## Deployment

- **Production Frontend:**  
  [https://secure-healthcare-patient-portal.vercel.app](https://secure-healthcare-patient-portal.vercel.app)  *(Vercel)*
- **Production Backend:**  
  Hosted on [Render](https://render.com/)
- **Production Database:**  
  Managed via [Supabase](https://supabase.com/)  
- **CI:**  
  Continuous deployment/integration enabled for seamless updates and security patching

---

## Directory Structure

```
/deliverables-2
│
├── backend/               # Python Flask/FastAPI backend with custom WAF
├── frontend/              # React/Next.js frontend code
├── requirements.txt       # Python dependencies
├── package.json           # JS dependencies (frontend)
├── .env.example           # Example environment variables
└── README.md              # (This documentation)
```

---

## Compliance & Best Practices

- Security controls modeled after healthcare sector best practices (HIPAA, OWASP Top Ten).
- All code, especially the WAF, is written for auditability and easy review by security teams.
- Privacy by design: Only necessary data is collected and all personally identifiable information (PII) is protected at every layer.

---

## Contact

For further technical details or collaboration inquiries, please refer to the repository or contact [aliuzair1](https://github.com/aliuzair1).

---
