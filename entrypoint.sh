#!/bin/sh
set -eu
PORT="${PORT:-8080}"
mkdir -p /run/clamav /var/lib/clamav /var/log/clamav
chown -R clamav:clamav /run/clamav /var/lib/clamav /var/log/clamav || true
freshclam || true
cat > /etc/clamav/clamd.conf <<'EOF'
LogTime yes
Foreground yes
TCPSocket 3310
TCPAddr 127.0.0.1
MaxScanSize 30M
MaxFileSize 25M
StreamMaxLength 25M
ReadTimeout 120
CommandReadTimeout 30
SendBufTimeout 500
DatabaseDirectory /var/lib/clamav
User clamav
EOF
clamd --foreground > /var/log/clamav/clamd.log 2>&1 &
PID=$!
i=0
until clamdscan --ping=5 >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -ge 60 ]; then cat /var/log/clamav/clamd.log || true; exit 1; fi
  sleep 2
done
freshclam --daemon --foreground=false || true
exec uvicorn app:app --host 0.0.0.0 --port "$PORT"
