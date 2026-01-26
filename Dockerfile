# CryptoLabs Proxy - Unified reverse proxy with fleet management
FROM nginx:alpine

LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/cryptolabs-proxy"
LABEL org.opencontainers.image.description="Unified reverse proxy for CryptoLabs products"
LABEL org.opencontainers.image.licenses="MIT"

# Build arguments for version info
ARG BUILD_BRANCH=unknown
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG VERSION=dev

# Install dependencies for health checks, auth, and Docker socket access
RUN apk add --no-cache \
    curl \
    python3 \
    py3-pip \
    docker-cli

# Install Python dependencies for service detection and authentication
RUN pip3 install --no-cache-dir --break-system-packages \
    pyyaml \
    requests \
    flask \
    werkzeug

# Copy Python source for auth module
COPY src/ /app/src/

# Copy landing page (can be overridden by volume)
COPY landing-page/ /usr/share/nginx/html/

# Copy default nginx config (typically overridden by volume mount)
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy scripts
COPY scripts/health-api.py /app/health-api.py
COPY scripts/auth-server.py /app/auth-server.py

# Copy entrypoint
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/auth-server.py

# Create directories for volume mounts
RUN mkdir -p /etc/nginx/ssl /etc/letsencrypt /var/www/certbot /data/auth

# Create BUILD_INFO file
RUN echo "VERSION=${VERSION}" > /app/BUILD_INFO && \
    echo "BRANCH=${BUILD_BRANCH}" >> /app/BUILD_INFO && \
    echo "COMMIT=${BUILD_COMMIT}" >> /app/BUILD_INFO && \
    echo "BUILD_DATE=${BUILD_DATE}" >> /app/BUILD_INFO && \
    echo "APP_NAME=CryptoLabs Fleet Management" >> /app/BUILD_INFO

# Volume mount points for persistent configuration
# These allow config to persist when container is recreated
VOLUME ["/etc/nginx/ssl", "/etc/letsencrypt", "/var/www/certbot", "/data"]

# Expose ports
EXPOSE 80 443

# Health check - check both nginx and health API
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/api/health && curl -f http://localhost:8080/api/health || exit 1

# Start both health-api and nginx
ENTRYPOINT ["/app/entrypoint.sh"]
