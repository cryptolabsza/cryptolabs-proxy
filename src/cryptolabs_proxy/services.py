"""Service registry for CryptoLabs Proxy."""

import subprocess
import json
import yaml
from pathlib import Path
from typing import Dict, Optional


# Default services that can be auto-detected
DEFAULT_SERVICES = {
    "ipmi-monitor": {
        "container_name": "ipmi-monitor",
        "path": "/ipmi/",
        "port": 5000,
        "display_name": "IPMI Monitor",
        "icon": "🖥️",
        "description": "Server hardware monitoring via IPMI/BMC",
        "product_url": "https://github.com/cryptolabsza/ipmi-monitor",
        "docs_url": "https://cryptolabs.co.za/ipmi-monitor/",
    },
    "dc-overview": {
        "container_name": "dc-overview",
        "path": "/dc/",
        "port": 5001,
        "display_name": "DC Overview",
        "icon": "📊",
        "description": "GPU Datacenter monitoring and management",
        "product_url": "https://github.com/cryptolabsza/dc-overview",
        "docs_url": "https://cryptolabs.co.za/dc-overview/",
    },
    "grafana": {
        "container_name": "grafana",
        "path": "/grafana/",
        "port": 3000,
        "display_name": "Grafana",
        "icon": "📈",
        "description": "Metrics visualization and dashboards",
        "product_url": "https://grafana.com/",
        "external": True,
    },
    "prometheus": {
        "container_name": "prometheus",
        "path": "/prometheus/",
        "port": 9090,
        "display_name": "Prometheus",
        "icon": "🔍",
        "description": "Metrics collection and alerting",
        "product_url": "https://prometheus.io/",
        "external": True,
        "auth_required": True,
    },
    "dc-watchdog": {
        "container_name": None,  # External service, not a container
        "path": None,  # Not proxied locally
        "port": None,
        "display_name": "DC Watchdog",
        "icon": "📡",
        "description": "External uptime monitoring and alerting",
        "product_url": "https://watchdog.cryptolabs.co.za",
        "docs_url": "https://watchdog.cryptolabs.co.za/docs",
        "external": True,
        "external_url": "https://watchdog.cryptolabs.co.za",  # Links to external service
        "requires_subscription": True,  # Requires CryptoLabs subscription
    },
    "vastai-exporter": {
        "container_name": "vastai-exporter",
        "path": "/vastai-metrics/",
        "port": 8622,
        "display_name": "Vast.ai Exporter",
        "icon": "💎",
        "description": "Prometheus exporter for Vast.ai metrics",
    },
    "runpod-exporter": {
        "container_name": "runpod-exporter",
        "path": "/runpod-metrics/",
        "port": 8623,
        "display_name": "RunPod Exporter",
        "icon": "🚀",
        "description": "Prometheus exporter for RunPod metrics",
    },
}


class ServiceRegistry:
    """Manage registered services for the proxy."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.services_file = config_dir / "services.yaml"
        self.config_file = config_dir / "config.yaml"
        self.services: Dict = {}
        self.config: Dict = {}
        self.load()
    
    def load(self):
        """Load services from file."""
        if self.services_file.exists():
            with open(self.services_file) as f:
                data = yaml.safe_load(f) or {}
                self.services = data.get("services", {})
        
        if self.config_file.exists():
            with open(self.config_file) as f:
                self.config = yaml.safe_load(f) or {}
    
    def save(self):
        """Save services to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.services_file, "w") as f:
            yaml.dump({"services": self.services}, f, default_flow_style=False)
        
        with open(self.config_file, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def add_service(
        self,
        name: str,
        container_name: str,
        path: str,
        port: int = 5000,
        display_name: str = None,
        icon: str = "🔧",
        description: str = "",
        **kwargs
    ):
        """Add or update a service."""
        self.services[name] = {
            "container_name": container_name,
            "path": path,
            "port": port,
            "display_name": display_name or name.replace("-", " ").title(),
            "icon": icon,
            "description": description,
            **kwargs
        }
        self.save()
    
    def remove_service(self, name: str):
        """Remove a service."""
        if name in self.services:
            del self.services[name]
            self.save()
    
    def get_service(self, name: str) -> Optional[Dict]:
        """Get a service by name."""
        return self.services.get(name)
    
    def check_health(self) -> Dict:
        """Check health of all services via Docker."""
        health = {}
        
        # Check proxy container
        try:
            result = subprocess.run(
                ["docker", "inspect", "cryptolabs-proxy"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data:
                    state = data[0].get("State", {})
                    health["proxy"] = {
                        "running": state.get("Running", False),
                        "healthy": state.get("Health", {}).get("Status") == "healthy" if state.get("Health") else state.get("Running", False)
                    }
        except:
            health["proxy"] = {"running": False, "healthy": False}
        
        # Check registered services
        for name, service in self.services.items():
            container = service.get("container_name", name)
            try:
                result = subprocess.run(
                    ["docker", "inspect", container],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    if data:
                        state = data[0].get("State", {})
                        health[name] = {
                            "running": state.get("Running", False),
                            "healthy": state.get("Health", {}).get("Status") == "healthy" if state.get("Health") else state.get("Running", False)
                        }
                else:
                    health[name] = {"running": False, "healthy": False}
            except:
                health[name] = {"running": False, "healthy": False}
        
        return health
    
    def auto_detect_services(self) -> Dict:
        """Auto-detect running CryptoLabs services."""
        detected = {}
        
        for name, defaults in DEFAULT_SERVICES.items():
            container = defaults.get("container_name", name)
            try:
                result = subprocess.run(
                    ["docker", "inspect", container],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    if data and data[0].get("State", {}).get("Running"):
                        detected[name] = {
                            **defaults,
                            "auto_detected": True
                        }
            except:
                pass
        
        return detected
