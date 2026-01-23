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

# Copy landing page
COPY landing-page/ /usr/share/nginx/html/

# Copy default nginx config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy health check script
COPY scripts/health-api.py /app/health-api.py

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/api/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
