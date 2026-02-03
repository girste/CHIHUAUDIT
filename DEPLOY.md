# CHIHUAUDIT — Deployment Guide

## Binary Deployment

### Quick Install
```bash
# Download binary
wget https://github.com/girste/chihuaudit/releases/latest/download/chihuaudit-linux-amd64
chmod +x chihuaudit-linux-amd64
sudo mv chihuaudit-linux-amd64 /usr/local/bin/chihuaudit

# Test
sudo chihuaudit audit
```

### Manual Build
```bash
git clone https://github.com/girste/chihuaudit
cd chihuaudit
make build
sudo cp bin/chihuaudit /usr/local/bin/
```

## Docker Deployment

### Quick Start
```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=DAC_READ_SEARCH \
  -v /etc:/host/etc:ro \
  -v /var/log:/host/var/log:ro \
  chihuaudit:latest audit
```

### Docker Compose (Monitoring)
```bash
docker-compose up -d
```

## Configuration

### Create config
```bash
sudo mkdir -p /etc/chihuaudit
sudo chihuaudit audit --format=json > /etc/chihuaudit/.chihuaudit.yaml
```

### Key settings
```yaml
scoring:
  minInterval: 10
  maxInterval: 86400
  baseScore: 100
  deductions:
    critical: 25
    high: 15
    medium: 10
    low: 5

notifications:
  enabled: true
  minSeverity: high
  discord:
    enabled: true
    webhookUrl: "https://discord.com/api/webhooks/..."
```

## MCP Server (Claude)

### Setup
```json
{
  "mcpServers": {
    "chihuaudit": {
      "command": "/usr/local/bin/chihuaudit",
      "args": []
    }
  }
}
```

## Systemd Service

### Create service
```bash
sudo tee /etc/systemd/system/chihuaudit.service << 'UNIT'
[Unit]
Description=Chihuaudit Security Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/chihuaudit daemon start
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl enable chihuaudit
sudo systemctl start chihuaudit
```

## Post-Deploy

### Verify
```bash
sudo chihuaudit version
sudo chihuaudit audit --format=summary
```

### Baseline
```bash
sudo chihuaudit baseline create
sudo chihuaudit baseline diff
```

### Test webhook
```bash
sudo chihuaudit audit --webhook
```
