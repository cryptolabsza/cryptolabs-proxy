#!/bin/sh
# CryptoLabs Proxy Entrypoint
# Starts health-api.py in background, then nginx in foreground

set -e

echo "[CryptoLabs Proxy] Starting health API..."
python3 /app/health-api.py &

echo "[CryptoLabs Proxy] Starting nginx..."
exec nginx -g "daemon off;"
