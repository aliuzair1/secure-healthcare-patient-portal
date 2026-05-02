FROM python:3.11-slim

WORKDIR /app

# Install system deps + Wazuh agent as root during build
RUN apt-get update -qq && \
    apt-get install -y curl gnupg && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
      gpg --no-default-keyring \
          --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
          --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.14.5-1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

RUN chmod +x start.sh
