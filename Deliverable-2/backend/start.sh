#!/bin/bash
# start.sh — Render startup script
# Installs Wazuh agent, configures log monitoring, starts Flask

set -e

echo "[start.sh] Installing Wazuh agent..."

# Download the Wazuh agent deb package
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb

# Install silently
WAZUH_MANAGER="${WAZUH_MANAGER_HOST}" \
WAZUH_AGENT_NAME="healthcare-render" \
dpkg -i ./wazuh-agent_4.14.5-1_amd64.deb 2>/dev/null || true

# ---------------------------------------------------------------
# Write the pre-generated agent key directly (bypasses port 1515)
# Format: <id> <name> <ip> <key>
# ---------------------------------------------------------------
echo "${WAZUH_AGENT_ID} healthcare-render any ${WAZUH_AGENT_KEY}" > /var/ossec/etc/client.keys
chmod 640 /var/ossec/etc/client.keys

# ---------------------------------------------------------------
# Write ossec.conf — points to Wazuh manager via ngrok tunnel
# and monitors the Flask + WAF log files
# ---------------------------------------------------------------
cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>

  <client>
    <server>
      <address>${WAZUH_MANAGER_HOST}</address>
      <port>${WAZUH_MANAGER_PORT}</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <!-- WAF attack log — blocked/challenged requests -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/waf_sig/logs/attack.log</location>
    <label key="log.source">waf_attack</label>
    <label key="log.environment">production</label>
  </localfile>

  <!-- WAF access log — all allowed requests -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/waf_sig/logs/access.log</location>
    <label key="log.source">waf_access</label>
    <label key="log.environment">production</label>
  </localfile>

  <!-- WAF error log -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/waf_sig/logs/error.log</location>
    <label key="log.source">waf_error</label>
    <label key="log.environment">production</label>
  </localfile>

  <!-- Flask application log — auth events, 500 errors -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/logs/app.log</location>
    <label key="log.source">flask_app</label>
    <label key="log.environment">production</label>
  </localfile>

</ossec_config>
EOF

echo "[start.sh] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || true

echo "[start.sh] Wazuh agent started. Starting Flask..."

# Start Flask via Gunicorn
exec gunicorn wsgi:application \
  --bind "0.0.0.0:${PORT:-10000}" \
  --workers 2 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
