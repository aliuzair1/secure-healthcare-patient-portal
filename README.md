# Secure Healthcare Patient Portal

This directory contains the production codebase for the Secure Healthcare Patient Portal, a full-stack healthcare web application engineered with comprehensive cybersecurity, privacy, and compliance best practices.

**Live Application:** [secure-healthcare-patient-portal.vercel.app](https://secure-healthcare-patient-portal.vercel.app)

---

## Overview

The Secure Healthcare Patient Portal enables secure patient and staff interaction with sensitive medical data. The application is architected with layered security controls, advanced threat detection, and robust deployment strategies to meet the demands of highly regulated environments.

- **Frontend:** JavaScript (React/Next.js), deployed on [Vercel](https://vercel.com/)
- **Backend:** Python (Flask/FastAPI), deployed on [Render](https://render.com/)
- **Database:** [Supabase](https://supabase.com/) (PostgreSQL)
- **SIEM:** [Wazuh](https://wazuh.com/) Security Information and Event Management integration for centralized monitoring and real-time threat analysis

---

## Security Architecture

Security is implemented at every layer through defense-in-depth. Major components include:

### Custom Web Application Firewall (WAF)

A bespoke Web Application Firewall (WAF) is integrated at the backend API layer with the following features:

- **Request Interception:** All HTTP requests are filtered before processing.
- **Input Validation:** Blocks SQL Injection, XSS, and other attacks using context-aware sanitization.
- **CSRF Protection:** Anti-CSRF tokens and referer/origin validation for state-changing requests.
- **Rate Limiting:** Defends against brute-force and enumeration attacks.
- **Anomaly Detection:** Monitors and blocks suspicious or automated traffic.
- **Structured Logging:** All security-relevant events, including blocks and anomalies, are logged for audit and monitoring.

### SIEM Integration (Wazuh)

- **Centralized Security Logging:** All security logs and WAF alerts are forwarded to a Wazuh SIEM server.
- **Automated Threat Detection:** Real-time analysis of logs for intrusion attempts, policy violations, and anomaly detection.
- **Compliance Reporting:** Automated generation of alerts and compliance-oriented audit reports.
- **Incident Response:** Enables rapid triage and response based on actionable Wazuh alerts integrated from backend and infrastructure sources.

#### Example WAF Rule Logic

```python
def waf_middleware(request):
    if has_sql_injection(request.data):
        log_event(type="blocked_sql_injection", user_ip=request.ip)
        send_to_wazuh(event="sql_injection", details=request.data)
        return deny_request("Blocked: SQL Injection detected.")
    if has_xss_payload(request.data):
        log_event(type="blocked_xss", user_ip=request.ip)
        send_to_wazuh(event="xss_attempt", details=request.data)
        return deny_request("Blocked: XSS attempt detected.")
    if exceeded_rate_limit(request):
        log_event(type="rate_limit", user_ip=request.ip)
        send_to_wazuh(event="rate_limit", user=request.user)
        return deny_request("Blocked: Rate limit exceeded.")
# ... additional rules
```

### Additional Security Measures

- **End-to-End Encryption:** All client–backend–database traffic enforced over HTTPS/TLS; at-rest data encryption in Supabase.
- **Authentication & Authorization:** Strong password hashing (bcrypt/argon2), JWT authentication, strict role-based access controls (RBAC).
- **Frontend Security:** CSP headers, output encoding, client-side validation integrated with backend security layers.
- **Logging & Auditing:** All significant actions and authentication events are securely logged and forwarded to Wazuh for centralized security operations and forensics.
- **Secure SDLC:** Adheres to modern secure development practices, automated dependency scans, and regular code review.

---

## Application Architecture

- **Frontend (Vercel):**  
  React/Next.js frontend, deployed with secure environment isolation and continuous deployment on [Vercel](https://secure-healthcare-patient-portal.vercel.app).
- **Backend (Render):**  
  Python REST API, custom WAF as middleware, independently deployed and scaled on [Render](https://render.com/).
- **Database (Supabase):**  
  PostgreSQL with Row-Level Security, cryptographic controls, and managed access policies.
- **Security Monitoring (Wazuh SIEM):**  
  All application and security logs are shipped to a dedicated Wazuh server for aggregation, analysis, patterned alerting, and compliance dashboards.

---

## Local Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/aliuzair1/secure-healthcare-patient-portal.git
    cd secure-healthcare-patient-portal/deliverables-2
    ```

2. **Backend Setup:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
    - Configure `.env` for secrets and Wazuh SIEM endpoint details.
    - Run backend server:
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
    - Configure Supabase credentials as per environment instructions.

---

## Deployment

- **Frontend (Production):**  
  [https://secure-healthcare-patient-portal.vercel.app](https://secure-healthcare-patient-portal.vercel.app)
- **Backend (Production):**  
  Hosted on [Render](https://render.com/)
- **Database:**  
  Managed via [Supabase](https://supabase.com/)
- **Security Monitoring:**  
  [Wazuh SIEM](https://wazuh.com/) for real-time threat detection and compliance
- **CI/CD:**  
  Automated via Vercel (frontend), Render (backend), and integrated testing

---

## Directory Structure

```
/deliverables-2
├── backend/               # Python backend + custom WAF
├── frontend/              # React/Next.js frontend
├── requirements.txt       # Python dependencies
├── package.json           # JS frontend dependencies
├── .env.example           # Example environment variables
└── README.md              # (This file)
```

---

## Compliance and Best Practices

- Controls and audit posture modeled on HIPAA and OWASP Top 10.
- Custom WAF, robust logging, and Wazuh SIEM integration provide proactive defense and incident response capabilities.
- Privacy by design: PII is minimized, compartmentalized, and encrypted from interface to storage.
- All code is engineered for auditability, traceability, and secure operation.

---
