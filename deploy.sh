#!/bin/bash
set -e

SERVER="root@157.230.149.230"
REMOTE_DIR="~/ClawGuard"

echo "==> Pushing local changes..."
git push

echo "==> Deploying to $SERVER..."
ssh "$SERVER" bash -s << 'EOF'
  set -e
  cd ~/ClawGuard
  git pull
  source .venv/bin/activate 2>/dev/null || true
  pip install -q -e . 2>/dev/null || true

  # Detect process manager and restart
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
EOF

echo "==> Done. Checking health..."
curl -sf http://157.230.149.230:8000/health && echo " OK" || echo " FAILED"
