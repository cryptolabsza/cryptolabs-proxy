#!/bin/sh
# CryptoLabs Proxy Entrypoint
# Starts auth-server, health-api in background, then nginx in foreground

set -e

# Create data directories
mkdir -p /data/auth

# Substitute site name in landing page
# Default to "CryptoLabs" if SITE_NAME is not set
SITE_NAME="${SITE_NAME:-CryptoLabs}"
if [ -f /usr/share/nginx/html/index.html ]; then
    sed -i "s/{{SITE_NAME}}/${SITE_NAME}/g" /usr/share/nginx/html/index.html
    echo "[CryptoLabs Proxy] Site name set to: ${SITE_NAME}"
fi

echo "[CryptoLabs Proxy] Starting authentication server..."
python3 /app/auth-server.py &

echo "[CryptoLabs Proxy] Starting health API..."
python3 /app/health-api.py &

# Wait a moment for services to start
sleep 1

echo "[CryptoLabs Proxy] Starting nginx..."
exec nginx -g "daemon off;"
