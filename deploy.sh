#!/bin/bash
set -e

SERVER="root@157.230.149.230"
REMOTE_DIR="/opt/ClawGuard"

echo "==> Deploying to $SERVER (pull + restart only)..."
ssh "$SERVER" bash -s << 'EOF'
  set -e
  cd /opt/ClawGuard
  git fetch origin
  git checkout main
  git pull origin main
  source .venv/bin/activate 2>/dev/null || true
  pip install -q -r requirements.txt 2>/dev/null || true

  # Setup nginx if not already configured
  if [ -f nginx/clawguard.conf ]; then
    if ! diff -q nginx/clawguard.conf /etc/nginx/sites-available/clawguard.conf &>/dev/null 2>&1; then
      echo "Updating nginx config..."
      cp nginx/clawguard.conf /etc/nginx/sites-available/clawguard.conf
      ln -sf /etc/nginx/sites-available/clawguard.conf /etc/nginx/sites-enabled/clawguard.conf
      rm -f /etc/nginx/sites-enabled/default
      nginx -t && systemctl reload nginx
    fi
  fi

  # Restart the API server
  if systemctl is-active --quiet clawguard 2>/dev/null; then
    echo "Restarting via systemd..."
    systemctl restart clawguard
  elif screen -list 2>/dev/null | grep -q clawguard; then
    echo "Restarting in screen session..."
    screen -S clawguard -X stuff "^C"
    sleep 1
    screen -S clawguard -X stuff "uvicorn clawguard.main:app --host 0.0.0.0 --port 8000\n"
  else
    echo "WARNING: No known process manager found. Restart manually."
    echo "  uvicorn clawguard.main:app --host 0.0.0.0 --port 8000"
  fi

  echo "==> Waiting for API to start..."
  sleep 3
EOF

echo "==> Checking health..."
curl -sf http://157.230.149.230:8000/health && echo " OK" || echo " FAILED (may need a few more seconds)"
