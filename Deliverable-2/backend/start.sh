#!/bin/bash
set -e

echo "[start.sh] Configuring Wazuh agent..."

# Write pre-generated agent key (bypasses port 1515 registration)
echo "${WAZUH_AGENT_ID} healthcare-render any ${WAZUH_AGENT_KEY}" \
  > /var/ossec/etc/client.keys
chmod 640 /var/ossec/etc/client.keys

# Write ossec.conf — log paths use /app since WORKDIR is /app in Dockerfile
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

  <localfile>
    <log_format>json</log_format>
    <location>/app/waf_sig/logs/attack.log</location>
    <label key="log.source">waf_attack</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/app/waf_sig/logs/access.log</location>
    <label key="log.source">waf_access</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/app/waf_sig/logs/error.log</location>
    <label key="log.source">waf_error</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/app/logs/app.log</location>
    <label key="log.source">flask_app</label>
    <label key="log.environment">production</label>
  </localfile>

</ossec_config>
EOF

echo "[start.sh] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || true

echo "[start.sh] Wazuh agent started. Starting Flask..."

exec gunicorn wsgi:application \
  --bind "0.0.0.0:${PORT:-10000}" \
  --workers 2 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
