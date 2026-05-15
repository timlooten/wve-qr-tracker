#!/bin/bash
# Deploy QR Tracker naar Berry
# Gebruik: ./deploy_berry.sh
# Berry hostname aanpassen als nodig

BERRY="michaelai@minivan-michael"
REMOTE_DIR="/home/michaelai/qr_tracker"

echo "==> Kopieer bestanden naar Berry..."
ssh "$BERRY" "mkdir -p $REMOTE_DIR"
scp qr_app.py requirements.txt "$BERRY:$REMOTE_DIR/"

echo "==> Installeer dependencies..."
ssh "$BERRY" "cd $REMOTE_DIR && python3 -m venv venv && venv/bin/pip install -q -r requirements.txt"

echo "==> Installeer systemd service..."
scp qr_tracker.service "$BERRY:/tmp/"
ssh "$BERRY" "sudo mv /tmp/qr_tracker.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable qr_tracker && sudo systemctl restart qr_tracker"

echo "==> Status:"
ssh "$BERRY" "sudo systemctl status qr_tracker --no-pager"

echo ""
echo "Klaar. Dashboard: http://berry-ip:5010/admin"
echo "Vergeet niet QR_ADMIN_PASSWORD in te stellen in qr_tracker.service!"
