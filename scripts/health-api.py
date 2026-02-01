#!/usr/bin/env python3
"""
Health API server for CryptoLabs Proxy.
Detects running Docker containers, reports their status, and manages updates.
"""

import json
import subprocess
import http.server
import socketserver
import threading
import os
import re
from urllib.parse import urlparse, parse_qs
from pathlib import Path

PORT = 8080
BUILD_INFO_FILE = '/app/BUILD_INFO'
SETTINGS_FILE = '/data/auth/update-settings.json'

# Services to check (Docker containers)
SERVICES = {
    'cryptolabs-proxy': {'container': 'cryptolabs-proxy', 'port': 8080, 'image': 'ghcr.io/cryptolabsza/cryptolabs-proxy', 'self': True},
    'ipmi-monitor': {'container': 'ipmi-monitor', 'port': 5000, 'image': 'ghcr.io/cryptolabsza/ipmi-monitor'},
    'dc-overview': {'container': 'dc-overview', 'port': 5001, 'image': 'ghcr.io/cryptolabsza/dc-overview'},
    'grafana': {'container': 'grafana', 'port': 3000, 'image': 'grafana/grafana', 'external': True},
    'prometheus': {'container': 'prometheus', 'port': 9090, 'image': 'prom/prometheus', 'external': True},
    'vastai-exporter': {'container': 'vastai-exporter', 'port': 8622, 'image': 'ghcr.io/cryptolabsza/vastai-exporter'},
    'runpod-exporter': {'container': 'runpod-exporter', 'port': 8623, 'image': 'ghcr.io/cryptolabsza/runpod-exporter'},
}


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


def pull_image(image_name, tag='latest'):
    """Pull a Docker image."""
    full_image = f"{image_name}:{tag}"
    try:
        result = subprocess.run(
            ['docker', 'pull', full_image],
            capture_output=True, text=True, timeout=300
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def get_container_config(container_name):
    """Get the configuration of a running container for restart."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', container_name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None
        
        data = json.loads(result.stdout)
        if not data:
            return None
        
        container = data[0]
        config = container.get('Config', {})
        host_config = container.get('HostConfig', {})
        network_settings = container.get('NetworkSettings', {})
        
        # Get network names
        networks = list(network_settings.get('Networks', {}).keys())
        
        # Get port bindings
        port_bindings = host_config.get('PortBindings', {})
        
        # Get volume bindings
        binds = host_config.get('Binds', []) or []
        
        # Get environment variables
        env_vars = config.get('Env', []) or []
        
        # Get restart policy
        restart_policy = host_config.get('RestartPolicy', {}).get('Name', 'unless-stopped')
        
        return {
            'networks': networks,
            'port_bindings': port_bindings,
            'binds': binds,
            'env_vars': env_vars,
            'restart_policy': restart_policy,
        }
    except Exception as e:
        print(f"Error getting container config for {container_name}: {e}")
        return None


def restart_container(container_name, image_with_tag, container_config):
    """Restart a container with the same configuration but new image."""
    if not container_config:
        return False, "No container configuration available"
    
    try:
        # Build docker run command
        cmd = ['docker', 'run', '-d', '--name', container_name]
        
        # Restart policy
        cmd.extend(['--restart', container_config.get('restart_policy', 'unless-stopped')])
        
        # Networks
        for network in container_config.get('networks', ['cryptolabs']):
            if network and network != 'bridge':
                cmd.extend(['--network', network])
        
        # Port bindings
        for container_port, host_bindings in container_config.get('port_bindings', {}).items():
            if host_bindings:
                for binding in host_bindings:
                    host_port = binding.get('HostPort', '')
                    host_ip = binding.get('HostIp', '')
                    if host_ip:
                        cmd.extend(['-p', f"{host_ip}:{host_port}:{container_port.split('/')[0]}"])
                    else:
                        cmd.extend(['-p', f"{host_port}:{container_port.split('/')[0]}"])
        
        # Volume bindings
        for bind in container_config.get('binds', []):
            cmd.extend(['-v', bind])
        
        # Environment variables (filter out build-time vars that we'll update)
        for env in container_config.get('env_vars', []):
            # Skip PATH and other system vars, keep user-defined ones
            if env.startswith('PATH=') or env.startswith('HOME='):
                continue
            cmd.extend(['-e', env])
        
        # Image
        cmd.append(image_with_tag)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return False, f"Failed to start container: {result.stderr}"
        
        return True, "Container restarted successfully"
    except Exception as e:
        return False, f"Error restarting container: {e}"


def update_container(container_name, service_config, target_branch='main'):
    """Update a container to a new image version."""
    image = service_config.get('image', '')
    if not image:
        return False, "No image configured for service"
    
    is_self = service_config.get('self', False)
    tag = target_branch if target_branch in ['dev', 'main'] else 'latest'
    
    # For external images, always use latest
    if service_config.get('external'):
        tag = 'latest'
    
    full_image = f"{image}:{tag}"
    
    # Pull new image first
    success, output = pull_image(image, tag)
    if not success:
        return False, f"Failed to pull image: {output}"
    
    if is_self:
        # For self-update, we need special handling
        # Create a script that will restart the container after we exit
        return True, "self-update-required"
    
    # Get current container configuration before stopping
    container_config = get_container_config(container_name)
    
    # Stop and remove old container
    try:
        subprocess.run(['docker', 'stop', container_name], capture_output=True, timeout=30)
        subprocess.run(['docker', 'rm', container_name], capture_output=True, timeout=10)
    except:
        pass
    
    # Restart container with new image
    if container_config:
        success, msg = restart_container(container_name, full_image, container_config)
        if success:
            return True, f"Updated to {tag} and restarted"
        else:
            return False, f"Image pulled but restart failed: {msg}"
    else:
        # Fallback: container wasn't running or couldn't get config
        return True, f"Image pulled. Container needs manual restart (was not running)."


def trigger_self_update(target_branch='main'):
    """Trigger self-update for the proxy container."""
    # Pull the new image
    image = 'ghcr.io/cryptolabsza/cryptolabs-proxy'
    tag = target_branch if target_branch in ['dev', 'main'] else 'latest'
    
    success, output = pull_image(image, tag)
    if not success:
        return False, f"Failed to pull image: {output}"
    
    # Create a restart script that runs after the API responds
    # This uses docker to restart the container from outside
    script = f"""#!/bin/bash
sleep 2
docker stop cryptolabs-proxy
docker rm cryptolabs-proxy
# The container should be recreated by docker-compose or systemd
# For safety, try to start it using the same command pattern
docker run -d --name cryptolabs-proxy \\
  --restart unless-stopped \\
  --network cryptolabs \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -v /data/auth:/data/auth \\
  -p 80:80 -p 443:443 \\
  {image}:{tag}
"""
    
    # Write script and execute in background
    script_path = '/tmp/proxy-update.sh'
    try:
        with open(script_path, 'w') as f:
            f.write(script)
        os.chmod(script_path, 0o755)
        subprocess.Popen(['/bin/bash', script_path], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        start_new_session=True)
        return True, "Self-update initiated. Proxy will restart in a few seconds."
    except Exception as e:
        return False, f"Failed to initiate self-update: {e}"


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
            'external': config.get('external', False),
            'self': config.get('self', False),
        }
        
        if include_versions and running:
            version_info = get_container_version(container)
            if version_info:
                service_info.update({
                    'version': version_info,
                    'current_branch': version_info.get('branch', 'unknown'),
                })
        
        status[name] = service_info
    
    return status


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
            'external': config.get('external', False),
            'self': config.get('self', False),
        }
        
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
        
        elif path == '/api/update':
            # Trigger update for one or all services
            service = data.get('service', 'all')
            target_branch = data.get('branch', load_update_settings().get('branch', 'main'))
            
            results = {}
            
            if service == 'all':
                # Update all services (including external like Grafana/Prometheus)
                for name, config in SERVICES.items():
                    if config.get('self'):
                        # Handle self-update last
                        continue
                    # For external services, we pull :latest (no branch suffix)
                    if config.get('external'):
                        success, msg = update_container(name, config, 'latest')
                    else:
                        success, msg = update_container(name, config, target_branch)
                    results[name] = {'success': success, 'message': msg}
                
                # Handle proxy self-update last (if requested)
                if 'cryptolabs-proxy' in SERVICES:
                    success, msg = trigger_self_update(target_branch)
                    results['cryptolabs-proxy'] = {'success': success, 'message': msg}
            
            elif service == 'cryptolabs-proxy':
                # Self-update
                success, msg = trigger_self_update(target_branch)
                results[service] = {'success': success, 'message': msg}
            
            elif service in SERVICES:
                config = SERVICES[service]
                if config.get('external'):
                    # External services use :latest tag
                    success, msg = update_container(service, config, 'latest')
                    results[service] = {'success': success, 'message': msg}
                else:
                    success, msg = update_container(service, config, target_branch)
                    results[service] = {'success': success, 'message': msg}
            
            else:
                self.send_json({'error': f'Unknown service: {service}'}, 400)
                return
            
            self.send_json({'success': True, 'results': results})
        
        elif path == '/api/pull':
            # Just pull images without restarting
            service = data.get('service', 'all')
            target_branch = data.get('branch', load_update_settings().get('branch', 'main'))
            
            results = {}
            services_to_pull = [service] if service != 'all' else list(SERVICES.keys())
            
            for name in services_to_pull:
                if name not in SERVICES:
                    results[name] = {'success': False, 'message': 'Unknown service'}
                    continue
                
                config = SERVICES[name]
                if config.get('external'):
                    tag = 'latest'
                else:
                    tag = target_branch if target_branch in ['dev', 'main'] else 'latest'
                
                image = config.get('image', '')
                if image:
                    success, msg = pull_image(image, tag)
                    results[name] = {'success': success, 'message': msg[:200] if len(msg) > 200 else msg}
                else:
                    results[name] = {'success': False, 'message': 'No image configured'}
            
            self.send_json({'success': True, 'results': results})
        
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging


if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), HealthHandler) as httpd:
        print(f"Health API running on port {PORT}")
        httpd.serve_forever()
