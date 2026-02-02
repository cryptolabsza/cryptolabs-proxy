"""Programmatic setup API for CryptoLabs Proxy.

This module provides functions that can be called by other CryptoLabs products
(dc-overview, ipmi-monitor) to set up the proxy without duplicating SSL logic.
"""

import os
import subprocess
import shutil
import secrets
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
PROXY_STATIC_IP = "172.30.0.2"


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
    
    def __post_init__(self):
        if not self.auth_secret:
            self.auth_secret = secrets.token_hex(32)
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


def get_proxy_config() -> Optional[Dict]:
    """Get current proxy configuration if running."""
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
        
        # Remove existing
        subprocess.run(["docker", "rm", "-f", "cryptolabs-proxy"], capture_output=True)
        
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
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "-v", "fleet-auth-data:/data/auth",
            "-v", f"{ssl_dir}:/etc/nginx/ssl:ro",
            "--network", DOCKER_NETWORK_NAME,
            "--ip", PROXY_STATIC_IP,
            "--label", "com.centurylinklabs.watchtower.enable=true",
            "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"
        ]
        
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
    
    # Step 5: Initialize service registry
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
        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
        "-v", "fleet-auth-data:/data/auth",
        "-v", f"{ssl_dir}:/etc/nginx/ssl:ro",
        "--network", DOCKER_NETWORK_NAME,
        "--ip", PROXY_STATIC_IP,
        "--label", "com.centurylinklabs.watchtower.enable=true",
        "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return False, f"Failed to restart proxy: {result.stderr[:200]}"
    
    return True, "Proxy credentials updated"
