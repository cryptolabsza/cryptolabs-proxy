"""CryptoLabs Proxy - Unified reverse proxy for CryptoLabs products."""

__version__ = "1.1.7"

# Export programmatic setup API
from .setup import (
    ProxyConfig,
    setup_proxy,
    is_proxy_running,
    get_proxy_config,
    get_internal_api_token,
    update_proxy_credentials,
    ensure_docker_network,
    check_existing_letsencrypt_cert,
    DOCKER_NETWORK_NAME,
    DOCKER_NETWORK_SUBNET,
    PROXY_STATIC_IP,
)

from .services import ServiceRegistry, DEFAULT_SERVICES

__all__ = [
    "ProxyConfig",
    "setup_proxy",
    "is_proxy_running",
    "get_proxy_config",
    "get_internal_api_token",
    "update_proxy_credentials",
    "ensure_docker_network",
    "check_existing_letsencrypt_cert",
    "ServiceRegistry",
    "DEFAULT_SERVICES",
    "DOCKER_NETWORK_NAME",
    "DOCKER_NETWORK_SUBNET",
    "PROXY_STATIC_IP",
]
