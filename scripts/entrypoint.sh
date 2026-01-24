#!/bin/sh
# CryptoLabs Proxy Entrypoint
# Starts auth-server, health-api in background, then nginx in foreground

set -e

# Create data directories
mkdir -p /data/auth

echo "[CryptoLabs Proxy] Starting authentication server..."
python3 /app/auth-server.py &

echo "[CryptoLabs Proxy] Starting health API..."
python3 /app/health-api.py &

# Wait a moment for services to start
sleep 1

echo "[CryptoLabs Proxy] Starting nginx..."
exec nginx -g "daemon off;"
