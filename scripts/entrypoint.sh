#!/bin/sh
# CryptoLabs Proxy Entrypoint
# Starts auth-server, health-api in background, then nginx in foreground

set -e

# Create data and log directories
mkdir -p /data/auth
mkdir -p /var/log/cryptolabs

echo "[CryptoLabs Proxy] ========================================"
echo "[CryptoLabs Proxy] Starting CryptoLabs Proxy..."
echo "[CryptoLabs Proxy] Build: $(cat /app/BUILD_INFO 2>/dev/null || echo 'unknown')"
echo "[CryptoLabs Proxy] ========================================"

# Substitute site name in landing page
# Default to "CryptoLabs" if SITE_NAME is not set
SITE_NAME="${SITE_NAME:-CryptoLabs}"
if [ -f /usr/share/nginx/html/index.html ]; then
    sed -i "s/{{SITE_NAME}}/${SITE_NAME}/g" /usr/share/nginx/html/index.html
    echo "[CryptoLabs Proxy] Site name set to: ${SITE_NAME}"
fi

# Start auth server with error logging
echo "[CryptoLabs Proxy] Starting authentication server on port 8081..."
python3 /app/auth-server.py 2>&1 | while read line; do echo "[AUTH] $line"; done &
AUTH_PID=$!

# Give auth server time to start and check if it's running
sleep 2
if ! kill -0 $AUTH_PID 2>/dev/null; then
    echo "[CryptoLabs Proxy] ERROR: Authentication server failed to start!"
    echo "[CryptoLabs Proxy] Check the [AUTH] log lines above for details."
    echo "[CryptoLabs Proxy] Common issues:"
    echo "[CryptoLabs Proxy]   - Missing Python dependencies"
    echo "[CryptoLabs Proxy]   - Syntax errors in auth code"
    echo "[CryptoLabs Proxy]   - Port 8081 already in use"
    # Don't exit - let nginx start anyway for debugging
fi

# Start health API with error logging
echo "[CryptoLabs Proxy] Starting health API on port 8082..."
python3 /app/health-api.py 2>&1 | while read line; do echo "[HEALTH] $line"; done &
HEALTH_PID=$!

# Wait a moment for services to start
sleep 1

# Verify auth server is listening
if nc -z 127.0.0.1 8081 2>/dev/null; then
    echo "[CryptoLabs Proxy] ✓ Auth server listening on port 8081"
else
    echo "[CryptoLabs Proxy] ⚠ WARNING: Auth server not responding on port 8081"
    echo "[CryptoLabs Proxy]   Authentication may not work correctly!"
fi

# Verify health API is listening
if nc -z 127.0.0.1 8082 2>/dev/null; then
    echo "[CryptoLabs Proxy] ✓ Health API listening on port 8082"
else
    echo "[CryptoLabs Proxy] ⚠ WARNING: Health API not responding on port 8082"
fi

# Check SSL certificates
if [ -f /etc/nginx/ssl/server.crt ] && [ -f /etc/nginx/ssl/server.key ]; then
    echo "[CryptoLabs Proxy] ✓ SSL certificates found"
else
    echo "[CryptoLabs Proxy] ⚠ WARNING: SSL certificates not found at /etc/nginx/ssl/"
    echo "[CryptoLabs Proxy]   Mount your certs: -v /path/to/ssl:/etc/nginx/ssl:ro"
fi

echo "[CryptoLabs Proxy] ========================================"
echo "[CryptoLabs Proxy] Starting nginx..."
exec nginx -g "daemon off;"
