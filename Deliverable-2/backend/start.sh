#!/bin/bash
set -e

echo "[start.sh] Adding Wazuh apt repository..."

# Write GPG key to /tmp (user-writable, avoids permission denied on /usr/share/keyrings)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring \
      --keyring gnupg-ring:/tmp/wazuh.gpg \
      --import
chmod 644 /tmp/wazuh.gpg

# Add apt source pointing to the /tmp keyring
echo "deb [signed-by=/tmp/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list > /dev/null

echo "[start.sh] Installing Wazuh agent 4.14.5..."
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.14.5-1

echo "[start.sh] Configuring agent key..."
sudo mkdir -p /var/ossec/etc
echo "${WAZUH_AGENT_ID} healthcare-render any ${WAZUH_AGENT_KEY}" \
  | sudo tee /var/ossec/etc/client.keys > /dev/null
sudo chmod 640 /var/ossec/etc/client.keys

echo "[start.sh] Writing ossec.conf..."
sudo tee /var/ossec/etc/ossec.conf > /dev/null << EOF
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
    <location>/opt/render/project/src/Deliverable-2/backend/waf_sig/logs/attack.log</location>
    <label key="log.source">waf_attack</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/waf_sig/logs/access.log</location>
    <label key="log.source">waf_access</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/waf_sig/logs/error.log</location>
    <label key="log.source">waf_error</label>
    <label key="log.environment">production</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/opt/render/project/src/Deliverable-2/backend/logs/app.log</location>
    <label key="log.source">flask_app</label>
    <label key="log.environment">production</label>
  </localfile>

</ossec_config>
EOF

echo "[start.sh] Starting Wazuh agent..."
sudo /var/ossec/bin/wazuh-control start || true

echo "[start.sh] Wazuh agent started. Starting Flask..."

exec gunicorn wsgi:application \
  --bind "0.0.0.0:${PORT:-10000}" \
  --workers 2 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
