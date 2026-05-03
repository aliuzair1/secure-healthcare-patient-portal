#!/bin/bash
set -e

echo "[start.sh] Configuring Wazuh agent..."

# Write pre-generated agent key — WAZUH_AGENT_KEY is the full base64-encoded
# record from the Wazuh API (decodes to "ID NAME IP HEX_KEY")
echo "${WAZUH_AGENT_KEY}" | base64 -d > /var/ossec/etc/client.keys
chmod 640 /var/ossec/etc/client.keys

echo "[start.sh] client.keys entry: $(awk '{print $1,$2,$3,"***"}' /var/ossec/etc/client.keys)"

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
    <location>/app/logs/attack.log</location>
    <label key="log.source">waf_attack</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/app/logs/access.log</location>
    <label key="log.source">waf_access</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/app/logs/error.log</location>
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

# Pre-create log files so Wazuh logcollector finds them at agent startup.
# Also write a startup test event so we can verify the pipeline immediately.
mkdir -p /app/logs
touch /app/logs/access.log /app/logs/error.log /app/logs/app.log
echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)\",\"level\":\"WARNING\",\"logger\":\"waf.attack\",\"message\":\"startup-test\",\"event_type\":\"attack\",\"client_ip\":\"127.0.0.1\",\"method\":\"GET\",\"path\":\"/startup-test\",\"action\":\"BLOCK\",\"risk_score\":0.99,\"risk_label\":\"CRITICAL\"}" \
  >> /app/logs/attack.log
echo "[start.sh] Wrote startup test event to attack.log"

echo "[start.sh] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || true

if pgrep -x wazuh-agentd > /dev/null 2>&1; then
  echo "[start.sh] wazuh-agentd is running."
else
  echo "[start.sh] wazuh-agentd failed — last ossec.log lines:"
  tail -20 /var/ossec/logs/ossec.log 2>/dev/null || echo "(no log file)"
fi

echo "[start.sh] Wazuh agent started. Starting Flask..."

exec gunicorn wsgi:application \
  --bind "0.0.0.0:${PORT:-10000}" \
  --workers 2 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
