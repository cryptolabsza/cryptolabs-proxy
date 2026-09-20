#!/usr/bin/env python3
"""
Health API server for CryptoLabs Proxy.
Detects running Docker containers, reports their status, and manages updates.
"""

import json
import subprocess
import time
import http.server
import socketserver
import threading
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from pathlib import Path

sys.path.insert(0, '/app/src')
from cryptolabs_proxy.vpm_prerequisite import get_vpm_prerequisite
from cryptolabs_proxy.updates import (
    SERVICES, UpdateBusy, UpdateError, job_status,
    submit_job as submit_update_job, update_status,
)

PORT = 8080
BUILD_INFO_FILE = '/app/BUILD_INFO'
SETTINGS_FILE = '/data/auth/update-settings.json'
SHARED_CONFIG_FILE = '/data/auth/shared-config.json'
VPM_READY_URL = 'http://vast-price-manager:8088/readyz'
VPM_PREREQUISITE_CACHE_TTL_SECONDS = 30
_VPM_PREREQUISITE_CACHE = {'expires_at': 0, 'value': None}

# Internal Docker network subnet - only allow requests from this range
INTERNAL_NETWORK = '172.30.'

# Shared secret for internal API authentication (set via INTERNAL_API_TOKEN env var)
# Must match the token given to dc-overview / ipmi-monitor containers
INTERNAL_API_TOKEN = os.environ.get('INTERNAL_API_TOKEN', '')

# Config keys classified by sensitivity
# PUBLIC: safe to return without auth (cosmetic / non-secret)
# INTERNAL: requires valid bearer token + internal network (API keys, etc.)
# NEVER: never returned via API (passwords, secrets)
PUBLIC_CONFIG_KEYS = {'site_name', 'watchdog_url'}
INTERNAL_CONFIG_KEYS = {'watchdog_api_key'}
NEVER_EXPOSE_KEYS = {'fleet_admin_pass', 'fleet_admin_user', 'auth_secret'}



def load_update_settings():
    """Load update settings from file."""
    defaults = {
        'branch': 'main',  # 'main' or 'dev'
        'auto_update': True,
        'update_schedule': 'daily',  # 'daily', 'weekly', or 'manual'
    }
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                saved = json.load(f)
                defaults.update(saved)
    except Exception:
        pass
    return defaults


def save_update_settings(settings):
    """Save update settings to file."""
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False


def load_shared_config():
    """Load the shared config store used by all fleet services.
    
    IMPORTANT: This function intentionally does NOT load passwords or secrets
    (fleet_admin_pass, auth_secret) into the config store. Those values should
    NEVER leave the container's environment. The filter_config_for_response()
    function provides an additional safety net, but defense-in-depth means
    we don't even load them here.
    """
    config = {}
    try:
        if os.path.exists(SHARED_CONFIG_FILE):
            with open(SHARED_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            # Scrub any sensitive keys that may have been persisted by accident
            for key in NEVER_EXPOSE_KEYS:
                config.pop(key, None)
    except Exception:
        pass

    # Merge in live NON-SENSITIVE values from environment
    env_keys = {
        'site_name': 'SITE_NAME',
        'watchdog_url': 'WATCHDOG_URL',
    }
    for config_key, env_var in env_keys.items():
        val = os.environ.get(env_var, '')
        if val:
            config[config_key] = val

    # Watchdog API key: check persistent file first (written by SSO callback),
    # then env var (set at deploy time)
    key_file = '/data/auth/watchdog_api_key'
    if os.path.exists(key_file):
        try:
            with open(key_file) as f:
                wk = f.read().strip()
                if wk:
                    config['watchdog_api_key'] = wk
        except Exception:
            pass
    if 'watchdog_api_key' not in config:
        wk = os.environ.get('WATCHDOG_API_KEY', '')
        if wk:
            config['watchdog_api_key'] = wk

    return config


def save_shared_config(config):
    """Save the shared config store.
    
    Scrubs sensitive keys before writing to prevent accidental persistence
    of passwords or secrets to the JSON config file.
    """
    try:
        # Defense-in-depth: never persist sensitive keys to disk
        clean_config = {k: v for k, v in config.items() if k not in NEVER_EXPOSE_KEYS}
        os.makedirs(os.path.dirname(SHARED_CONFIG_FILE), exist_ok=True)
        with open(SHARED_CONFIG_FILE, 'w') as f:
            json.dump(clean_config, f, indent=2)
        # Config file is readable by containers on the shared volume,
        # but only contains non-sensitive data
        os.chmod(SHARED_CONFIG_FILE, 0o644)
        return True
    except Exception as e:
        print(f"Error saving shared config: {e}")
        return False


def is_internal_request(client_address):
    """Check if the request comes from the internal Docker network."""
    ip = client_address[0] if isinstance(client_address, tuple) else str(client_address)
    return ip.startswith(INTERNAL_NETWORK) or ip == '127.0.0.1' or ip == '::1'


# Rate limiting for failed auth attempts (defense-in-depth)
_failed_auth_attempts = {}  # ip -> (count, first_attempt_time)
_MAX_FAILED_ATTEMPTS = 10
_LOCKOUT_SECONDS = 300  # 5 minute lockout after 10 failures


def _check_rate_limit(client_address) -> bool:
    """Return True if the client is rate-limited (too many failed auth attempts)."""
    ip = client_address[0] if isinstance(client_address, tuple) else str(client_address)
    if ip not in _failed_auth_attempts:
        return False
    count, first_time = _failed_auth_attempts[ip]
    import time
    elapsed = time.time() - first_time
    if elapsed > _LOCKOUT_SECONDS:
        # Reset after lockout period
        del _failed_auth_attempts[ip]
        return False
    return count >= _MAX_FAILED_ATTEMPTS


def _record_failed_auth(client_address):
    """Record a failed authentication attempt for rate limiting."""
    ip = client_address[0] if isinstance(client_address, tuple) else str(client_address)
    import time
    now = time.time()
    if ip in _failed_auth_attempts:
        count, first_time = _failed_auth_attempts[ip]
        if now - first_time > _LOCKOUT_SECONDS:
            _failed_auth_attempts[ip] = (1, now)
        else:
            _failed_auth_attempts[ip] = (count + 1, first_time)
    else:
        _failed_auth_attempts[ip] = (1, now)
    count = _failed_auth_attempts[ip][0]
    if count >= _MAX_FAILED_ATTEMPTS:
        print(f"WARNING: IP {ip} locked out after {count} failed auth attempts")


def verify_internal_token(headers):
    """Verify the bearer token for internal API access to sensitive keys.
    
    Returns True only if INTERNAL_API_TOKEN is set AND the request has
    a matching Authorization: Bearer <token> header.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not INTERNAL_API_TOKEN:
        return False
    auth_header = headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        import hmac
        return hmac.compare_digest(auth_header[7:], INTERNAL_API_TOKEN)
    return False


def filter_config_for_response(config, has_token=False):
    """Return only the config keys the caller is allowed to see.
    
    - Always: PUBLIC_CONFIG_KEYS (site_name, watchdog_url)
    - With valid token: + INTERNAL_CONFIG_KEYS (watchdog_api_key)
    - Never: NEVER_EXPOSE_KEYS (passwords, secrets)
    """
    allowed = set(PUBLIC_CONFIG_KEYS)
    if has_token:
        allowed |= INTERNAL_CONFIG_KEYS
    return {k: v for k, v in config.items() if k in allowed}


def check_container_running(container_name):
    """Check if a Docker container is running."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.State.Running}}', container_name],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == 'true'
    except:
        return False


def get_vast_price_manager_allowed_host():
    """Read only VPM's non-secret public-host setting from Docker inspect."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{range .Config.Env}}{{println .}}{{end}}', 'vast-price-manager'],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        for env_line in result.stdout.splitlines():
            if env_line.startswith('VPM_ALLOWED_HOSTS='):
                host = env_line.split('=', 1)[1].split(',', 1)[0].strip()
                return host or None
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_vast_price_manager_docker_health():
    """Return Docker's VPM healthcheck result without treating running as healthy."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', 'vast-price-manager'], capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        return data[0].get('State', {}).get('Health', {}).get('Status') if data else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError):
        return None


def get_vast_price_manager_readiness():
    """Report VPM account setup separately from Docker liveness.

    VPM's Docker healthcheck uses ``/healthz``.  Its ``/readyz`` endpoint is
    surfaced for Fleet status only, so an unconfigured account never creates a
    liveness restart loop.
    """
    allowed_host = get_vast_price_manager_allowed_host()
    if not allowed_host:
        return 'unavailable'
    try:
        request = Request(VPM_READY_URL, headers={'Host': allowed_host})
        with urlopen(request, timeout=2) as response:
            return 'ready' if response.status == 200 else 'unavailable'
    except HTTPError as error:
        return 'unconfigured' if error.code == 503 else 'unavailable'
    except (URLError, OSError, TimeoutError):
        return 'unavailable'


def service_action_error(service_name):
    """Return an error when lifecycle is owned outside generic proxy updates."""
    config = SERVICES.get(service_name, {})
    if config.get('update_supported') is False:
        display_name = 'Vast Price Manager' if service_name == 'vast-price-manager' else service_name
        return f"{display_name} lifecycle is managed by {config['lifecycle_manager']}."
    return None


def get_container_version(container_name):
    """Get version info for a container from its image, labels, and environment variables."""
    try:
        # Get image name
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.Config.Image}}', container_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None
        
        image = result.stdout.strip()
        
        # Extract tag from image name
        tag = 'latest'
        if ':' in image:
            tag = image.split(':')[-1]
        
        # Get labels
        label_result = subprocess.run(
            ['docker', 'inspect', '--format', 
             '{{index .Config.Labels "org.opencontainers.image.version"}}||{{index .Config.Labels "org.opencontainers.image.revision"}}||{{index .Config.Labels "build.time"}}'],
            capture_output=True, text=True, timeout=5
        )
        version = ''
        revision = ''
        label_build_time = ''
        if label_result.returncode == 0:
            parts = label_result.stdout.strip().split('||')
            version = parts[0] if len(parts) > 0 and parts[0] else ''
            revision = parts[1] if len(parts) > 1 and parts[1] else ''
            label_build_time = parts[2] if len(parts) > 2 and parts[2] else ''
        
        # Get environment variables individually for better parsing
        git_commit = ''
        git_branch = ''
        build_time = ''
        
        # Get GIT_COMMIT
        env_result = subprocess.run(
            ['docker', 'inspect', '--format', '{{range .Config.Env}}{{println .}}{{end}}', container_name],
            capture_output=True, text=True, timeout=5
        )
        if env_result.returncode == 0:
            for line in env_result.stdout.strip().split('\n'):
                if line.startswith('GIT_COMMIT='):
                    git_commit = line.split('=', 1)[1][:8]  # First 8 chars of commit
                elif line.startswith('GIT_BRANCH='):
                    git_branch = line.split('=', 1)[1]
                elif line.startswith('BUILD_TIME='):
                    build_time = line.split('=', 1)[1]
        
        # Try to get created time if no build time found
        if not build_time and not label_build_time:
            created_result = subprocess.run(
                ['docker', 'inspect', '--format', '{{.Created}}', container_name],
                capture_output=True, text=True, timeout=5
            )
            if created_result.returncode == 0:
                created = created_result.stdout.strip()
                # Parse ISO format and simplify
                if 'T' in created:
                    build_time = created.split('T')[0]  # Just the date
        
        # Determine branch from tag if not set
        if not git_branch:
            if tag == 'dev':
                git_branch = 'dev'
            elif tag in ['latest', 'main']:
                git_branch = 'main'
            else:
                git_branch = tag
        
        return {
            'image': image,
            'tag': tag,
            'version': version or tag,
            'commit': revision or git_commit,
            'branch': git_branch,
            'build_time': build_time or label_build_time,
        }
    except Exception as e:
        print(f"Error getting version for {container_name}: {e}")
        return None


def get_all_service_status(include_versions=False):
    """Get status of all services."""
    status = {}
    settings = load_update_settings()
    
    for name, config in SERVICES.items():
        container = config['container']
        running = check_container_running(container)
        
        service_info = {
            'running': running,
            'healthy': running,
            'container': container,
            'port': config['port'],
            'image': config.get('image', ''),
            'self': config.get('self', False),
        }

        if config.get('lifecycle_manager'):
            service_info['lifecycle_manager'] = config['lifecycle_manager']
            service_info['update_supported'] = config.get('update_supported', True)

        if name == 'vast-price-manager':
            readiness = get_vast_price_manager_readiness() if running else 'not-installed'
            docker_health = get_vast_price_manager_docker_health() if running else None
            service_info.update({
                'healthy': docker_health == 'healthy',
                'docker_health': docker_health,
                'readiness': readiness,
                'configured': readiness == 'ready',
                'state': 'running' if readiness == 'ready' else readiness,
                'prerequisite': get_vpm_prerequisite_for_display(),
            })
        
        if include_versions and running:
            version_info = get_container_version(container)
            if version_info:
                service_info.update({
                    'version': version_info,
                    'current_branch': version_info.get('branch', 'unknown'),
                })
        
        status[name] = service_info
    
    return status


def get_vpm_prerequisite_for_display():
    """Cache the sanitized prerequisite only for status-page polling."""
    now = time.monotonic()
    cached = _VPM_PREREQUISITE_CACHE
    if cached['value'] is not None and now < cached['expires_at']:
        return cached['value']
    value = get_vpm_prerequisite()
    _VPM_PREREQUISITE_CACHE['value'] = value
    _VPM_PREREQUISITE_CACHE['expires_at'] = now + VPM_PREREQUISITE_CACHE_TTL_SECONDS
    return value


def get_all_versions():
    """Get version info for all services."""
    versions = {}
    settings = load_update_settings()
    
    for name, config in SERVICES.items():
        container = config['container']
        running = check_container_running(container)
        
        version_info = {
            'container': container,
            'running': running,
            'image': config.get('image', ''),
            'self': config.get('self', False),
        }
        if config.get('lifecycle_manager'):
            version_info['lifecycle_manager'] = config['lifecycle_manager']
            version_info['update_supported'] = config.get('update_supported', True)
        
        if running:
            v = get_container_version(container)
            if v:
                version_info.update({
                    'tag': v.get('tag', 'unknown'),
                    'commit': v.get('commit', 'unknown'),
                    'branch': v.get('branch', 'unknown'),
                    'build_time': v.get('build_time', 'unknown'),
                    'version': v.get('version', 'unknown'),
                })
        else:
            version_info.update({
                'tag': 'not running',
                'commit': '',
                'branch': '',
                'build_time': '',
                'version': 'not running',
            })
        
        versions[name] = version_info
        if running and config.get('update_supported') is not False:
            version_info.update(update_status(name, settings.get('branch', 'main')))
    
    # Add configured branch
    versions['_settings'] = {
        'target_branch': settings.get('branch', 'main'),
        'auto_update': settings.get('auto_update', True),
        'update_schedule': settings.get('update_schedule', 'daily'),
    }
    
    return versions


def get_build_info():
    """Read build info from BUILD_INFO file."""
    try:
        with open(BUILD_INFO_FILE, 'r') as f:
            info = {}
            for line in f:
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    info[key.lower()] = value
            return info
    except FileNotFoundError:
        return {
            'version': 'dev',
            'branch': 'unknown',
            'commit': 'unknown',
            'build_date': 'unknown',
            'app_name': 'CryptoLabs Fleet Management'
        }


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Fleet-Auth-Token')
        self.end_headers()
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        
        if path == '/api/services':
            include_versions = query.get('versions', ['0'])[0] == '1'
            status = get_all_service_status(include_versions=include_versions)
            self.send_json(status)
        
        elif path == '/api/health':
            self.send_json({'status': 'ok'})
        
        elif path == '/api/build-info':
            build_info = get_build_info()
            self.send_json(build_info)
        
        elif path == '/api/versions':
            versions = get_all_versions()
            self.send_json(versions)
        
        elif path == '/api/update-settings':
            settings = load_update_settings()
            self.send_json(settings)

        elif path == '/api/update-status':
            try:
                self.send_json(job_status(query.get('id', [''])[0]))
            except UpdateError as error:
                self.send_json({'error': str(error)}, 404)
        
        # ---- Internal Config API (fleet services only) ----
        # Security: 4 layers of protection
        #   1. nginx blocks /internal/ for all public traffic (returns 403)
        #   2. IP check: must come from internal Docker network (172.30.x.x)
        #   3. Rate limiting: lockout after repeated failed auth attempts
        #   4. Bearer token required for sensitive keys (watchdog_api_key, etc.)
        elif path == '/internal/api/config':
            if not is_internal_request(self.client_address):
                self.send_json({'error': 'Forbidden'}, 403)
                return
            if _check_rate_limit(self.client_address):
                self.send_json({'error': 'Too many failed attempts'}, 429)
                return
            has_token = verify_internal_token(self.headers)
            if not has_token and self.headers.get('Authorization'):
                _record_failed_auth(self.client_address)
            config = load_shared_config()
            self.send_json(filter_config_for_response(config, has_token))
        
        elif path.startswith('/internal/api/config/'):
            if not is_internal_request(self.client_address):
                self.send_json({'error': 'Forbidden'}, 403)
                return
            if _check_rate_limit(self.client_address):
                self.send_json({'error': 'Too many failed attempts'}, 429)
                return
            key = path.split('/internal/api/config/', 1)[1]
            # Block keys that should never be exposed
            if key in NEVER_EXPOSE_KEYS:
                self.send_json({'error': 'Forbidden'}, 403)
                return
            # Sensitive keys require bearer token
            if key in INTERNAL_CONFIG_KEYS:
                if not verify_internal_token(self.headers):
                    _record_failed_auth(self.client_address)
                    self.send_json({'error': 'Unauthorized - bearer token required'}, 401)
                    return
            config = load_shared_config()
            if key in config:
                self.send_json({'key': key, 'value': config[key]})
            else:
                self.send_json({'error': f'Key not found: {key}'}, 404)
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
            return
        
        if path == '/api/update-settings':
            # Update settings
            current = load_update_settings()
            
            if 'branch' in data:
                if data['branch'] in ['main', 'dev']:
                    current['branch'] = data['branch']
                else:
                    self.send_json({'error': 'Invalid branch. Use "main" or "dev"'}, 400)
                    return
            
            if 'auto_update' in data:
                current['auto_update'] = bool(data['auto_update'])
            
            if 'update_schedule' in data:
                if data['update_schedule'] in ['daily', 'weekly', 'manual']:
                    current['update_schedule'] = data['update_schedule']
            
            if save_update_settings(current):
                self.send_json({'success': True, 'settings': current})
            else:
                self.send_json({'error': 'Failed to save settings'}, 500)
        
        elif path in ('/api/update', '/api/pull'):
            try:
                job = submit_update_job(
                    data.get('service', 'all'),
                    data.get('branch', load_update_settings().get('branch', 'main')),
                    'pull' if path == '/api/pull' else 'update',
                )
                self.send_json({'success': True, 'job': job}, 202)
            except UpdateBusy as error:
                self.send_json({'success': False, 'error': str(error), 'job': error.job}, 409)
            except UpdateError as error:
                self.send_json({'success': False, 'error': str(error)}, 400)
            except Exception:
                self.send_json({'success': False, 'error': 'Updater unavailable; no update confirmed.'}, 503)

        # ---- Internal Config API: SET values (always requires token) ----
        elif path == '/internal/api/config':
            if not is_internal_request(self.client_address):
                self.send_json({'error': 'Forbidden'}, 403)
                return
            if _check_rate_limit(self.client_address):
                self.send_json({'error': 'Too many failed attempts'}, 429)
                return
            if not verify_internal_token(self.headers):
                _record_failed_auth(self.client_address)
                self.send_json({'error': 'Unauthorized - bearer token required'}, 401)
                return
            # Strip out any keys that should never be stored via API
            config = load_shared_config()
            updated_keys = []
            for k, v in data.items():
                if k in NEVER_EXPOSE_KEYS:
                    continue  # silently skip
                config[k] = v
                updated_keys.append(k)
            if save_shared_config(config):
                self.send_json({'success': True, 'updated': updated_keys})
            else:
                self.send_json({'error': 'Failed to save config'}, 500)
        
        elif path.startswith('/internal/api/config/'):
            if not is_internal_request(self.client_address):
                self.send_json({'error': 'Forbidden'}, 403)
                return
            if _check_rate_limit(self.client_address):
                self.send_json({'error': 'Too many failed attempts'}, 429)
                return
            if not verify_internal_token(self.headers):
                _record_failed_auth(self.client_address)
                self.send_json({'error': 'Unauthorized - bearer token required'}, 401)
                return
            key = path.split('/internal/api/config/', 1)[1]
            if key in NEVER_EXPOSE_KEYS:
                self.send_json({'error': 'Forbidden'}, 403)
                return
            value = data.get('value')
            if value is None:
                self.send_json({'error': 'Missing "value" in request body'}, 400)
                return
            config = load_shared_config()
            config[key] = value
            if save_shared_config(config):
                self.send_json({'success': True, 'key': key})
            else:
                self.send_json({'error': 'Failed to save config'}, 500)
        
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging


if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), HealthHandler) as httpd:
        print(f"Health API running on port {PORT}")
        httpd.serve_forever()
