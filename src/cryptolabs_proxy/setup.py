"""Programmatic setup API for CryptoLabs Proxy.

This module provides functions that can be called by other CryptoLabs products
(dc-overview, ipmi-monitor) to set up the proxy without duplicating SSL logic.
"""

import os
import subprocess
import shutil
import secrets
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
from datetime import datetime

from .config import generate_nginx_config, generate_docker_compose, CONFIG_DIR
from .ssl import generate_self_signed_cert
from .services import ServiceRegistry


# Docker network configuration
DOCKER_NETWORK_NAME = "cryptolabs"
DOCKER_NETWORK_SUBNET = "172.30.0.0/16"
PROXY_STATIC_IP = "172.30.0.10"  # Use .10 to avoid conflicts with other containers


@dataclass
class ProxyConfig:
    """Configuration for proxy setup."""
    domain: str
    email: str = ""
    use_letsencrypt: bool = True
    fleet_admin_user: str = "admin"
    fleet_admin_pass: str = ""
    auth_secret: str = ""
    site_name: str = "DC Overview"  # Displayed on landing page
    additional_tcp_ports: List[int] = None
    additional_udp_ports: List[int] = None
    # DC Watchdog SSO - API key enables auto-login from Fleet Management
    watchdog_api_key: str = ""
    watchdog_url: str = "https://watchdog.cryptolabs.co.za"
    # Internal API token - shared secret for service-to-service config API
    internal_api_token: str = ""
    
    def __post_init__(self):
        if not self.auth_secret:
            self.auth_secret = secrets.token_hex(32)
        if not self.internal_api_token:
            self.internal_api_token = secrets.token_hex(32)
        if self.additional_tcp_ports is None:
            self.additional_tcp_ports = []
        if self.additional_udp_ports is None:
            self.additional_udp_ports = []


def get_local_ip() -> str:
    """Get local IP address."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def is_proxy_running() -> bool:
    """Check if cryptolabs-proxy container is running."""
    result = subprocess.run(
        ["docker", "inspect", "cryptolabs-proxy", "--format", "{{.State.Running}}"],
        capture_output=True, text=True
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def wait_for_container_healthy(
    container_name: str, 
    timeout: int = 120, 
    check_interval: int = 5,
    callback=None
) -> bool:
    """Wait for a container to be healthy.
    
    Args:
        container_name: Name of the Docker container
        timeout: Maximum seconds to wait (default 2 minutes)
        check_interval: Seconds between checks
        callback: Optional function(msg) for progress updates
        
    Returns:
        True if container is healthy, False if timeout
    """
    import time
    waited = 0
    
    while waited < timeout:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}:{{.State.Health.Status}}",
             container_name],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            status = result.stdout.strip()
            parts = status.split(":")
            is_running = parts[0] == "true"
            health = parts[1] if len(parts) > 1 else ""
            
            if is_running and health == "healthy":
                return True
            
            # Show progress every 30 seconds
            if callback and waited > 0 and waited % 30 == 0:
                callback(f"  Still waiting for {container_name} (health: {health}) [{waited}s/{timeout}s]")
        
        time.sleep(check_interval)
        waited += check_interval
    
    return False


# Keys that should never be returned by get_proxy_config() to prevent leaking
# secrets to callers that don't need them (e.g. quickstart scripts)
_SENSITIVE_ENV_KEYS = {'INTERNAL_API_TOKEN', 'AUTH_SECRET_KEY'}


def _save_internal_token(token: str):
    """Save the internal API token to the shared volume so other containers can read it.
    
    File is written to the fleet-auth-data volume with restricted permissions (0600)
    since only the host process deploying containers needs to read it.
    """
    token_dir = CONFIG_DIR / "auth"
    token_dir.mkdir(parents=True, exist_ok=True)
    token_file = token_dir / "internal_api_token"
    token_file.write_text(token)
    import os as _os
    _os.chmod(token_file, 0o600)


def get_internal_api_token() -> Optional[str]:
    """Read the internal API token from disk (for use by deployment scripts).
    
    This is called by quickstart scripts to pass the token to dc-overview/ipmi-monitor
    containers as an environment variable.
    """
    token_file = CONFIG_DIR / "auth" / "internal_api_token"
    if token_file.exists():
        try:
            return token_file.read_text().strip()
        except Exception:
            pass
    # Fallback: read from proxy container env
    try:
        result = subprocess.run(
            ["docker", "inspect", "cryptolabs-proxy", "--format",
             "{{range .Config.Env}}{{println .}}{{end}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.startswith('INTERNAL_API_TOKEN='):
                    return line.split('=', 1)[1]
    except Exception:
        pass
    return None


def get_proxy_config() -> Optional[Dict]:
    """Get current proxy configuration if running.
    
    Note: Sensitive keys (INTERNAL_API_TOKEN, AUTH_SECRET_KEY) are filtered out.
    Use get_internal_api_token() to retrieve the internal API token specifically.
    """
    if not is_proxy_running():
        return None
    
    try:
        result = subprocess.run(
            ["docker", "inspect", "cryptolabs-proxy", "--format",
             "{{range .Config.Env}}{{println .}}{{end}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None
        
        config = {}
        for line in result.stdout.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                # Filter out sensitive internal keys
                if key not in _SENSITIVE_ENV_KEYS:
                    config[key] = value
        return config
    except Exception:
        return None


def check_existing_letsencrypt_cert(domain: str) -> Tuple[bool, Optional[Path], Optional[Path]]:
    """Check if a valid Let's Encrypt certificate exists for the domain.
    
    Returns:
        Tuple of (is_valid, cert_path, key_path)
    """
    cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    key_path = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    
    if not cert_path.exists() or not key_path.exists():
        return False, None, None
    
    # Check if cert is valid (not expiring within 7 days = 604800 seconds)
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "604800"],
        capture_output=True
    )
    
    if result.returncode == 0:
        return True, cert_path, key_path
    else:
        return False, cert_path, key_path


def obtain_letsencrypt_cert(domain: str, email: str) -> bool:
    """Obtain a new Let's Encrypt certificate.
    
    Stops any services on port 80 temporarily.
    """
    # Install certbot if needed
    if not shutil.which("certbot"):
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
        subprocess.run(["apt-get", "install", "-y", "-qq", "certbot"], capture_output=True)
    
    if not shutil.which("certbot"):
        return False
    
    # Stop services on port 80/443
    subprocess.run(["systemctl", "stop", "nginx"], capture_output=True)
    subprocess.run(["docker", "stop", "cryptolabs-proxy"], capture_output=True)
    
    # Give time for ports to be released
    import time
    time.sleep(2)
    
    cmd = [
        "certbot", "certonly", "--standalone",
        "-d", domain,
        "--email", email,
        "--agree-tos",
        "--non-interactive",
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.returncode == 0


def ensure_ssl_certs(config: ProxyConfig) -> Tuple[bool, str]:
    """Ensure SSL certificates are available.
    
    Returns:
        Tuple of (success, message)
    """
    ssl_dir = CONFIG_DIR / "ssl"
    ssl_dir.mkdir(parents=True, exist_ok=True)
    
    if config.use_letsencrypt and config.domain:
        # Check for existing valid LE cert
        is_valid, cert_path, key_path = check_existing_letsencrypt_cert(config.domain)
        
        if is_valid:
            # Copy existing cert to proxy SSL dir
            shutil.copy2(cert_path, ssl_dir / "server.crt")
            shutil.copy2(key_path, ssl_dir / "server.key")
            os.chmod(ssl_dir / "server.key", 0o600)
            
            # Set up renewal hook
            _setup_renewal_hook(config.domain)
            
            return True, f"Using existing Let's Encrypt certificate for {config.domain}"
        
        # Try to obtain new cert
        if config.email:
            if obtain_letsencrypt_cert(config.domain, config.email):
                # Copy newly obtained cert
                cert_path = Path(f"/etc/letsencrypt/live/{config.domain}/fullchain.pem")
                key_path = Path(f"/etc/letsencrypt/live/{config.domain}/privkey.pem")
                shutil.copy2(cert_path, ssl_dir / "server.crt")
                shutil.copy2(key_path, ssl_dir / "server.key")
                os.chmod(ssl_dir / "server.key", 0o600)
                
                # Set up renewal hook
                _setup_renewal_hook(config.domain)
                
                return True, f"Obtained new Let's Encrypt certificate for {config.domain}"
        
        # Fall back to self-signed
        generate_self_signed_cert(ssl_dir, config.domain)
        return False, f"Could not obtain Let's Encrypt cert, using self-signed for {config.domain}"
    
    else:
        # Generate self-signed cert
        domain = config.domain or get_local_ip()
        generate_self_signed_cert(ssl_dir, domain)
        return True, f"Generated self-signed certificate for {domain}"


def _setup_renewal_hook(domain: str):
    """Set up certbot renewal hook to copy certs to proxy."""
    hook_dir = Path("/etc/letsencrypt/renewal-hooks/deploy")
    hook_dir.mkdir(parents=True, exist_ok=True)
    
    hook_script = hook_dir / "copy-to-proxy.sh"
    hook_content = f'''#!/bin/bash
# Auto-generated by cryptolabs-proxy
# Copy renewed certs to proxy SSL directory
cp /etc/letsencrypt/live/{domain}/fullchain.pem /etc/cryptolabs-proxy/ssl/server.crt
cp /etc/letsencrypt/live/{domain}/privkey.pem /etc/cryptolabs-proxy/ssl/server.key
chmod 644 /etc/cryptolabs-proxy/ssl/server.crt
chmod 600 /etc/cryptolabs-proxy/ssl/server.key
docker exec cryptolabs-proxy nginx -s reload 2>/dev/null || true
'''
    hook_script.write_text(hook_content)
    hook_script.chmod(0o755)


def ensure_docker_network() -> bool:
    """Ensure the cryptolabs Docker network exists with correct subnet."""
    # Check if network exists
    result = subprocess.run(
        ["docker", "network", "inspect", DOCKER_NETWORK_NAME],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        # Network exists, check subnet
        import json
        try:
            data = json.loads(result.stdout)
            if data:
                configs = data[0].get("IPAM", {}).get("Config", [])
                for cfg in configs:
                    if cfg.get("Subnet") == DOCKER_NETWORK_SUBNET:
                        return True
                
                # Wrong subnet, remove and recreate
                subprocess.run(["docker", "network", "rm", DOCKER_NETWORK_NAME], capture_output=True)
        except Exception:
            pass
    
    # Create network with correct subnet
    result = subprocess.run([
        "docker", "network", "create",
        "--driver", "bridge",
        "--subnet", DOCKER_NETWORK_SUBNET,
        DOCKER_NETWORK_NAME
    ], capture_output=True, text=True)
    
    return result.returncode == 0


def _free_ports_80_443() -> None:
    """Free up ports 80 and 443 before starting the proxy.
    
    This stops:
    - Host nginx service (if running)
    - Any existing cryptolabs-proxy container (including stuck/Created ones)
    - Apache2 if running
    """
    # Stop host web servers
    subprocess.run(["systemctl", "stop", "nginx"], capture_output=True)
    subprocess.run(["systemctl", "disable", "nginx"], capture_output=True)
    subprocess.run(["systemctl", "stop", "apache2"], capture_output=True)
    subprocess.run(["systemctl", "disable", "apache2"], capture_output=True)
    
    # Force remove any existing proxy container (handles "Created" state too)
    subprocess.run(["docker", "rm", "-f", "cryptolabs-proxy"], capture_output=True)
    
    # Give time for ports to be released
    time.sleep(1)
    
    # Check if ports are actually free using ss/netstat
    result = subprocess.run(
        ["ss", "-tlnp"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if ':80 ' in line or ':443 ' in line:
                # Try to identify and stop the process
                # Extract PID if available (format: users:(("name",pid=123,fd=4)))
                import re
                pid_match = re.search(r'pid=(\d+)', line)
                if pid_match:
                    pid = pid_match.group(1)
                    subprocess.run(["kill", "-9", pid], capture_output=True)
    
    time.sleep(1)


def setup_proxy(
    config: ProxyConfig,
    callback=None
) -> Tuple[bool, str]:
    """Set up or update the CryptoLabs proxy.
    
    This is the main entry point for programmatic setup.
    
    Args:
        config: ProxyConfig with all settings
        callback: Optional function(message: str) for progress updates
    
    Returns:
        Tuple of (success, message)
    """
    def log(msg: str):
        if callback:
            callback(msg)
    
    # Ensure config directory exists
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Step 1: SSL certificates
    log("Checking SSL certificates...")
    ssl_success, ssl_message = ensure_ssl_certs(config)
    log(ssl_message)
    
    # Step 2: Docker network
    log("Ensuring Docker network exists...")
    if not ensure_docker_network():
        return False, "Failed to create Docker network"
    log(f"Docker network '{DOCKER_NETWORK_NAME}' ready")
    
    # Step 3: Check if proxy needs update
    existing_config = get_proxy_config()
    needs_restart = False
    
    if existing_config:
        # Check if credentials changed
        if (existing_config.get("FLEET_ADMIN_USER") != config.fleet_admin_user or
            existing_config.get("FLEET_ADMIN_PASS") != config.fleet_admin_pass):
            needs_restart = True
            log("Credentials changed, will restart proxy")
    else:
        needs_restart = True
    
    # Step 4: Start/restart proxy
    if needs_restart:
        log("Starting proxy container...")
        
        # Free up ports 80/443 - stops nginx, apache, existing proxy containers
        log("Freeing ports 80/443...")
        _free_ports_80_443()
        
        # Pull latest image
        subprocess.run(
            ["docker", "pull", "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"],
            capture_output=True, timeout=120
        )
        
        ssl_dir = CONFIG_DIR / "ssl"
        
        cmd = [
            "docker", "run", "-d",
            "--name", "cryptolabs-proxy",
            "--restart", "unless-stopped",
            "-p", "80:80", "-p", "443:443",
            "-e", f"FLEET_ADMIN_USER={config.fleet_admin_user}",
            "-e", f"FLEET_ADMIN_PASS={config.fleet_admin_pass}",
            "-e", f"AUTH_SECRET_KEY={config.auth_secret}",
            "-e", f"SITE_NAME={config.site_name}",
            "-e", f"WATCHDOG_API_KEY={config.watchdog_api_key}",
            "-e", f"WATCHDOG_URL={config.watchdog_url}",
            "-e", f"INTERNAL_API_TOKEN={config.internal_api_token}",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "-v", "fleet-auth-data:/data/auth",
            "-v", f"{ssl_dir}:/etc/nginx/ssl:ro",
            "--network", DOCKER_NETWORK_NAME,
            "--ip", PROXY_STATIC_IP,
            "--label", "com.centurylinklabs.watchtower.enable=true",
            "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"
        ]
        
        # Save internal API token to shared volume so other containers can read it
        _save_internal_token(config.internal_api_token)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return False, f"Failed to start proxy: {result.stderr[:200]}"
        
        # Wait for container to be healthy (up to 2 minutes)
        log("Waiting for proxy to be healthy...")
        if not wait_for_container_healthy("cryptolabs-proxy", timeout=120, callback=log):
            return False, "Proxy failed to become healthy within 2 minutes"
        
        log("Proxy container started and healthy")
    else:
        log("Proxy already running with correct config")
    
    # Step 5: Ensure watchtower is running (cryptolabs-proxy owns it; primary for auto-updates)
    # Migrate from legacy dc-watchtower if present; then ensure cryptolabs-watchtower runs
    WATCHTOWER_CONTAINER = "cryptolabs-watchtower"
    LEGACY_WATCHTOWER = "dc-watchtower"
    
    wt_running = False
    try:
        r = subprocess.run(
            ["docker", "inspect", WATCHTOWER_CONTAINER, "--format", "{{.State.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        wt_running = r.returncode == 0 and r.stdout.strip() == "running"
    except Exception:
        pass
    
    if not wt_running:
        # Stop and remove legacy dc-watchtower (was deployed by dc-overview/ipmi-monitor)
        subprocess.run(["docker", "stop", LEGACY_WATCHTOWER], capture_output=True)
        subprocess.run(["docker", "rm", LEGACY_WATCHTOWER], capture_output=True)
        
        log("Starting cryptolabs-watchtower for automatic proxy updates...")
        wt_cmd = [
            "docker", "run", "-d",
            "--name", WATCHTOWER_CONTAINER,
            "--restart", "unless-stopped",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-e", "WATCHTOWER_CLEANUP=true",
            "-e", "WATCHTOWER_POLL_INTERVAL=300",
            "-e", "WATCHTOWER_LABEL_ENABLE=true",
            "-e", "WATCHTOWER_INCLUDE_STOPPED=true",
            "-e", "WATCHTOWER_ROLLING_RESTART=true",
            "--network", DOCKER_NETWORK_NAME,
            "--label", "com.centurylinklabs.watchtower.enable=true",
            "containrrr/watchtower"
        ]
        subprocess.run(wt_cmd, capture_output=True)
        log("Cryptolabs-watchtower started")
    else:
        log("Cryptolabs-watchtower already running")
    
    # Step 6: Initialize service registry
    registry = ServiceRegistry(CONFIG_DIR)
    registry.config["domain"] = config.domain
    registry.config["letsencrypt"] = config.use_letsencrypt and ssl_success
    registry.save()
    
    domain = config.domain or get_local_ip()
    return True, f"Proxy ready at https://{domain}/"


def update_proxy_credentials(
    fleet_admin_user: str,
    fleet_admin_pass: str,
    auth_secret: str = None,
    watchdog_api_key: str = None,
    watchdog_url: str = None
) -> Tuple[bool, str]:
    """Update proxy with new Fleet credentials without full restart.
    
    Used when dc-overview or ipmi-monitor needs to set/update credentials.
    """
    if not is_proxy_running():
        return False, "Proxy is not running"
    
    if not auth_secret:
        auth_secret = secrets.token_hex(32)
    
    # Get current container config to preserve settings
    existing = get_proxy_config()
    if not existing:
        return False, "Could not read proxy configuration"
    
    # Preserve existing watchdog config if not provided
    if watchdog_api_key is None:
        watchdog_api_key = existing.get("WATCHDOG_API_KEY", "")
    if watchdog_url is None:
        watchdog_url = existing.get("WATCHDOG_URL", "https://watchdog.cryptolabs.co.za")
    
    # Preserve or generate internal API token
    internal_api_token = existing.get("INTERNAL_API_TOKEN", "") or secrets.token_hex(32)
    
    # Recreate with new credentials
    subprocess.run(["docker", "rm", "-f", "cryptolabs-proxy"], capture_output=True)
    
    ssl_dir = CONFIG_DIR / "ssl"
    
    cmd = [
        "docker", "run", "-d",
        "--name", "cryptolabs-proxy",
        "--restart", "unless-stopped",
        "-p", "80:80", "-p", "443:443",
        "-e", f"FLEET_ADMIN_USER={fleet_admin_user}",
        "-e", f"FLEET_ADMIN_PASS={fleet_admin_pass}",
        "-e", f"AUTH_SECRET_KEY={auth_secret}",
        "-e", f"WATCHDOG_API_KEY={watchdog_api_key}",
        "-e", f"WATCHDOG_URL={watchdog_url}",
        "-e", f"INTERNAL_API_TOKEN={internal_api_token}",
        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
        "-v", "fleet-auth-data:/data/auth",
        "-v", f"{ssl_dir}:/etc/nginx/ssl:ro",
        "--network", DOCKER_NETWORK_NAME,
        "--ip", PROXY_STATIC_IP,
        "--label", "com.centurylinklabs.watchtower.enable=true",
        "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"
    ]
    
    _save_internal_token(internal_api_token)
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return False, f"Failed to restart proxy: {result.stderr[:200]}"
    
    return True, "Proxy credentials updated"
