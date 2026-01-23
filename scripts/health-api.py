#!/usr/bin/env python3
"""
Health API server for CryptoLabs Proxy.
Detects running Docker containers and reports their status.
"""

import json
import subprocess
import http.server
import socketserver
from urllib.parse import urlparse

PORT = 8080

# Services to check
SERVICES = {
    'ipmi-monitor': {'container': 'ipmi-monitor', 'port': 5000},
    'dc-overview': {'container': 'dc-overview', 'port': 5001},  # DC Overview uses port 5001
    'grafana': {'container': 'grafana', 'port': 3000},
    'prometheus': {'container': 'prometheus', 'port': 9090},
}


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


def get_all_service_status():
    """Get status of all services."""
    status = {}
    for name, config in SERVICES.items():
        running = check_container_running(config['container'])
        status[name] = {
            'running': running,
            'healthy': running,  # Could add actual health check
            'container': config['container'],
            'port': config['port']
        }
    return status


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == '/api/services':
            status = get_all_service_status()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(status).encode())
        
        elif path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging


if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), HealthHandler) as httpd:
        print(f"Health API running on port {PORT}")
        httpd.serve_forever()
