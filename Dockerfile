# CryptoLabs Proxy - Unified reverse proxy with fleet management
FROM nginx:alpine

LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/cryptolabs-proxy"
LABEL org.opencontainers.image.description="Unified reverse proxy for CryptoLabs products"
LABEL org.opencontainers.image.licenses="MIT"

# Install dependencies for health checks and Docker socket access
RUN apk add --no-cache \
    curl \
    python3 \
    py3-pip \
    docker-cli

# Install Python dependencies for service detection
RUN pip3 install --no-cache-dir --break-system-packages \
    pyyaml \
    requests

# Copy landing page (can be overridden by volume)
COPY landing-page/ /usr/share/nginx/html/

# Copy default nginx config (typically overridden by volume mount)
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy health check script
COPY scripts/health-api.py /app/health-api.py

# Copy entrypoint
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create directories for volume mounts
RUN mkdir -p /etc/nginx/ssl /etc/letsencrypt /var/www/certbot

# Volume mount points for persistent configuration
# These allow config to persist when container is recreated
VOLUME ["/etc/nginx/ssl", "/etc/letsencrypt", "/var/www/certbot"]

# Expose ports
EXPOSE 80 443

# Health check - check both nginx and health API
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/api/health && curl -f http://localhost:8080/api/health || exit 1

# Start both health-api and nginx
ENTRYPOINT ["/app/entrypoint.sh"]
