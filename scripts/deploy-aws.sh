#!/usr/bin/env bash
# One-shot setup for a fresh Ubuntu 22.04/24.04 EC2 instance.
# Run it on the server:  bash scripts/deploy-aws.sh
set -euo pipefail

echo "=== SecretShield deployment ==="

if ! command -v docker >/dev/null 2>&1; then
  echo "--- Installing Docker ---"
  sudo apt-get update -qq
  sudo apt-get install -y -qq ca-certificates curl git
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker "$USER"
  echo "Docker installed. Log out and back in if you hit a permission error."
else
  echo "Docker is already installed."
fi

if [ ! -f .env ]; then
  echo "--- Creating .env with a fresh ingest token ---"
  TOKEN="sshield_$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
  cat > .env <<EOF
INGEST_TOKEN=$TOKEN
DB_PATH=/srv/data/secretshield.db
LOG_PATH=/srv/logs/secretshield.log
EOF
  chmod 600 .env
  echo
  echo "  ============================================================"
  echo "  INGEST TOKEN (copy this into the GitHub secret SECRETSHIELD_TOKEN):"
  echo "  $TOKEN"
  echo "  ============================================================"
  echo
else
  echo ".env already exists; leaving it alone."
fi

echo "--- Building and starting the containers ---"
sudo docker compose up -d --build

echo "--- Waiting for the health check ---"
for i in $(seq 1 30); do
  if curl -fsS http://localhost/health >/dev/null 2>&1; then
    echo "Service is healthy."
    break
  fi
  sleep 2
done

PUBLIC_IP="$(curl -fsS --max-time 5 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")"
echo
echo "=== Done ==="
if [ -n "$PUBLIC_IP" ]; then
  echo "Dashboard:  http://$PUBLIC_IP/"
  echo "Health:     http://$PUBLIC_IP/health"
else
  echo "Dashboard:  http://<your-ec2-public-ip>/"
fi
echo
echo "Logs:    sudo docker compose logs -f"
echo "Restart: sudo docker compose restart"
