"""Manage optional exporter services (Vast.ai, RunPod).

Handles the full lifecycle:
- Enable: store API key, start container, add Prometheus scrape target, import Grafana dashboard
- Disable: stop container, remove Prometheus target, remove Grafana dashboard, clear API key
"""

import json
import subprocess
import logging
import time
import base64
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)

# Where we persist exporter config
EXPORTER_CONFIG_FILE = Path("/data/auth/exporter-config.json")

# Container definitions
EXPORTERS = {
    "vastai": {
        "container_name": "vastai-exporter",
        "image": "ghcr.io/cryptolabsza/vastai-exporter:latest",
        "port": 8622,
        "network": "cryptolabs",
        "display_name": "Vast.ai Exporter",
        "prometheus_job": "vastai",
        "scrape_interval": "60s",
        "dashboard_uid": "vast-dashboard",
        "dashboard_name": "Vast.ai Dashboard",
        "key_placeholder": "Your Vast.ai API Key",
        "key_help": "Find your API key at console.vast.ai → Account → API Keys",
    },
    "runpod": {
        "container_name": "runpod-exporter",
        "image": "ghcr.io/cryptolabsza/runpod-exporter:latest",
        "port": 8623,
        "network": "cryptolabs",
        "display_name": "RunPod Exporter",
        "prometheus_job": "runpod",
        "scrape_interval": "60s",
        "dashboard_uid": "runpod-dashboard",
        "dashboard_name": "RunPod Dashboard",
        "key_placeholder": "rpa_XXXXXXXXXXXXX",
        "key_help": "Find your API key at runpod.io → Settings → API Keys",
    },
}

# Dashboard JSON file paths inside the dc-overview container
DASHBOARD_PATHS = {
    "vastai": "/app/src/dc_overview/dashboards/Vast_Dashboard.json",
    "runpod": "/app/src/dc_overview/dashboards/RunPod_Dashboard.json",
}


def _load_config() -> dict:
    """Load exporter configuration."""
    if EXPORTER_CONFIG_FILE.exists():
        try:
            return json.loads(EXPORTER_CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


def _save_config(config: dict):
    """Save exporter configuration."""
    EXPORTER_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    EXPORTER_CONFIG_FILE.write_text(json.dumps(config, indent=2))


def get_exporter_status() -> dict:
    """Get status of all exporters."""
    config = _load_config()
    status = {}

    for name, exporter in EXPORTERS.items():
        container = exporter["container_name"]
        running = _is_container_running(container)
        enabled = config.get(name, {}).get("enabled", False)
        has_key = bool(config.get(name, {}).get("api_key"))

        status[name] = {
            "display_name": exporter["display_name"],
            "enabled": enabled,
            "running": running,
            "has_key": has_key,
            "port": exporter["port"],
            "key_placeholder": exporter["key_placeholder"],
            "key_help": exporter["key_help"],
        }

    return status


def enable_exporter(name: str, api_key: str) -> dict:
    """Enable an exporter: start container, configure Prometheus, import Grafana dashboard.

    Args:
        name: 'vastai' or 'runpod'
        api_key: The API key for the service

    Returns:
        dict with 'success' bool and 'steps' list of what was done
    """
    if name not in EXPORTERS:
        return {"success": False, "error": f"Unknown exporter: {name}"}

    if not api_key or not api_key.strip():
        return {"success": False, "error": "API key is required"}

    api_key = api_key.strip()
    exporter = EXPORTERS[name]
    steps = []

    # 1. Save config
    config = _load_config()
    config[name] = {"enabled": True, "api_key": api_key}
    _save_config(config)
    steps.append("Configuration saved")

    # 2. Start container
    success, msg = _start_exporter_container(name, api_key)
    steps.append(f"Container: {msg}")
    if not success:
        return {"success": False, "error": msg, "steps": steps}

    # 3. Add Prometheus scrape target
    success, msg = _add_prometheus_target(name)
    steps.append(f"Prometheus: {msg}")

    # 4. Import Grafana dashboard
    success, msg = _import_grafana_dashboard(name)
    steps.append(f"Grafana: {msg}")

    return {"success": True, "steps": steps}


def disable_exporter(name: str) -> dict:
    """Disable an exporter: stop container, remove Prometheus target, remove Grafana dashboard.

    Args:
        name: 'vastai' or 'runpod'

    Returns:
        dict with 'success' bool and 'steps' list of what was done
    """
    if name not in EXPORTERS:
        return {"success": False, "error": f"Unknown exporter: {name}"}

    exporter = EXPORTERS[name]
    steps = []

    # 1. Stop and remove container
    success, msg = _stop_exporter_container(name)
    steps.append(f"Container: {msg}")

    # 2. Remove Prometheus scrape target
    success, msg = _remove_prometheus_target(name)
    steps.append(f"Prometheus: {msg}")

    # 3. Remove Grafana dashboard
    success, msg = _remove_grafana_dashboard(name)
    steps.append(f"Grafana: {msg}")

    # 4. Clear config
    config = _load_config()
    config[name] = {"enabled": False, "api_key": ""}
    _save_config(config)
    steps.append("Configuration cleared")

    return {"success": True, "steps": steps}


# =============================================================================
# Docker Container Management
# =============================================================================

def _is_container_running(container_name: str) -> bool:
    """Check if a Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() == "true"
    except Exception:
        return False


def _start_exporter_container(name: str, api_key: str) -> tuple:
    """Start an exporter container."""
    exporter = EXPORTERS[name]
    container = exporter["container_name"]

    # Stop existing if running
    if _is_container_running(container):
        subprocess.run(["docker", "stop", container], capture_output=True, timeout=15)
        subprocess.run(["docker", "rm", container], capture_output=True, timeout=10)

    # Also remove stopped container with same name
    subprocess.run(["docker", "rm", container], capture_output=True, timeout=10)

    try:
        # Pull latest image
        pull = subprocess.run(
            ["docker", "pull", exporter["image"]],
            capture_output=True, text=True, timeout=120,
        )
        if pull.returncode != 0:
            logger.warning(f"Pull warning for {exporter['image']}: {pull.stderr}")

        # Build command - format key as "Default:key" for the exporter
        cmd = [
            "docker", "run", "-d",
            "--name", container,
            "--restart", "unless-stopped",
            "--network", exporter["network"],
            "-p", f"{exporter['port']}:{exporter['port']}",
            exporter["image"],
            "-api-key", api_key,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return False, f"Failed to start: {result.stderr.strip()}"

        # Verify it's running
        time.sleep(2)
        if _is_container_running(container):
            return True, f"Started {container}"
        else:
            # Get logs for debugging
            logs = subprocess.run(
                ["docker", "logs", "--tail", "10", container],
                capture_output=True, text=True, timeout=5,
            )
            return False, f"Container exited: {logs.stderr.strip() or logs.stdout.strip()}"

    except Exception as e:
        return False, f"Error: {str(e)}"


def _stop_exporter_container(name: str) -> tuple:
    """Stop and remove an exporter container."""
    container = EXPORTERS[name]["container_name"]
    try:
        subprocess.run(["docker", "stop", container], capture_output=True, timeout=15)
        subprocess.run(["docker", "rm", container], capture_output=True, timeout=10)
        return True, f"Stopped and removed {container}"
    except Exception as e:
        return False, f"Error stopping: {str(e)}"


# =============================================================================
# Prometheus Configuration
# =============================================================================

def _get_prometheus_config() -> tuple:
    """Read Prometheus config from the container. Returns (config_dict, raw_text)."""
    try:
        result = subprocess.run(
            ["docker", "exec", "prometheus", "cat", "/etc/prometheus/prometheus.yml"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None, None
        raw = result.stdout
        return yaml.safe_load(raw), raw
    except Exception:
        return None, None


def _write_prometheus_config(config: dict) -> bool:
    """Write Prometheus config back to the container and reload."""
    try:
        config_yaml = yaml.dump(config, default_flow_style=False, sort_keys=False)

        # Write via docker exec (pipe through sh -c)
        result = subprocess.run(
            ["docker", "exec", "-i", "prometheus", "sh", "-c",
             "cat > /etc/prometheus/prometheus.yml"],
            input=config_yaml, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            logger.error(f"Failed to write prometheus config: {result.stderr}")
            return False

        # Reload prometheus
        reload_result = subprocess.run(
            ["docker", "exec", "prometheus", "wget", "-q", "--spider",
             "http://localhost:9090/-/reload", "--post-data=''"],
            capture_output=True, text=True, timeout=10,
        )
        # wget --spider returns 0 on success
        if reload_result.returncode != 0:
            # Try kill -HUP instead
            subprocess.run(
                ["docker", "kill", "-s", "HUP", "prometheus"],
                capture_output=True, timeout=10,
            )

        return True
    except Exception as e:
        logger.error(f"Failed to update prometheus config: {e}")
        return False


def _add_prometheus_target(name: str) -> tuple:
    """Add a scrape target for the exporter to Prometheus config."""
    exporter = EXPORTERS[name]
    config, raw = _get_prometheus_config()
    if config is None:
        return False, "Cannot read Prometheus config (is Prometheus running?)"

    scrape_configs = config.get("scrape_configs", [])

    # Check if job already exists
    for sc in scrape_configs:
        if sc.get("job_name") == exporter["prometheus_job"]:
            return True, "Scrape target already exists"

    # Add new scrape config
    new_job = {
        "job_name": exporter["prometheus_job"],
        "scrape_interval": exporter["scrape_interval"],
        "static_configs": [
            {"targets": [f"{exporter['container_name']}:{exporter['port']}"]}
        ],
    }
    scrape_configs.append(new_job)
    config["scrape_configs"] = scrape_configs

    if _write_prometheus_config(config):
        return True, f"Added scrape target '{exporter['prometheus_job']}'"
    return False, "Failed to write Prometheus config"


def _remove_prometheus_target(name: str) -> tuple:
    """Remove the scrape target for the exporter from Prometheus config."""
    exporter = EXPORTERS[name]
    config, raw = _get_prometheus_config()
    if config is None:
        return False, "Cannot read Prometheus config"

    scrape_configs = config.get("scrape_configs", [])
    original_len = len(scrape_configs)
    scrape_configs = [sc for sc in scrape_configs if sc.get("job_name") != exporter["prometheus_job"]]

    if len(scrape_configs) == original_len:
        return True, "Scrape target was already removed"

    config["scrape_configs"] = scrape_configs

    if _write_prometheus_config(config):
        return True, f"Removed scrape target '{exporter['prometheus_job']}'"
    return False, "Failed to write Prometheus config"


# =============================================================================
# Grafana Dashboard Management
# =============================================================================

def _get_grafana_credentials() -> tuple:
    """Get Grafana URL and auth header."""
    grafana_url = "http://grafana:3000"

    # Get Grafana admin password from container env
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{range .Config.Env}}{{println .}}{{end}}", "grafana"],
            capture_output=True, text=True, timeout=5,
        )
        password = "admin"  # default
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.startswith("GF_SECURITY_ADMIN_PASSWORD="):
                    password = line.split("=", 1)[1]
                    break

        auth = base64.b64encode(f"admin:{password}".encode()).decode()
        return grafana_url, auth
    except Exception:
        auth = base64.b64encode(b"admin:admin").decode()
        return grafana_url, auth


def _get_dashboard_json(name: str) -> str:
    """Get dashboard JSON from the dc-overview container."""
    path = DASHBOARD_PATHS.get(name)
    if not path:
        return None

    try:
        result = subprocess.run(
            ["docker", "exec", "dc-overview", "cat", path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except Exception:
        pass

    return None


def _get_prometheus_datasource_uid(grafana_url: str, auth_header: str) -> str:
    """Get the Prometheus datasource UID from Grafana."""
    import urllib.request

    try:
        req = urllib.request.Request(
            f"{grafana_url}/api/datasources/name/Prometheus",
            headers={
                "Authorization": f"Basic {auth_header}",
                "X-WEBAUTH-USER": "admin",
            },
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        return data.get("uid", "prometheus")
    except Exception:
        return "prometheus"


def _fix_datasource_refs(obj, uid: str):
    """Recursively fix datasource references in a dashboard JSON object."""
    if isinstance(obj, dict):
        if obj.get("type") == "prometheus" or obj.get("type") == "datasource":
            obj["uid"] = uid
        if "datasource" in obj and isinstance(obj["datasource"], dict):
            if obj["datasource"].get("type") == "prometheus":
                obj["datasource"]["uid"] = uid
        for v in obj.values():
            _fix_datasource_refs(v, uid)
    elif isinstance(obj, list):
        for item in obj:
            _fix_datasource_refs(item, uid)


def _import_grafana_dashboard(name: str) -> tuple:
    """Import a dashboard into Grafana via API."""
    import urllib.request

    grafana_url, auth_header = _get_grafana_credentials()
    dashboard_json = _get_dashboard_json(name)

    if not dashboard_json:
        return False, "Dashboard JSON not found (is dc-overview running?)"

    try:
        dash_obj = json.loads(dashboard_json)

        # Get Prometheus datasource UID
        prom_uid = _get_prometheus_datasource_uid(grafana_url, auth_header)
        _fix_datasource_refs(dash_obj, prom_uid)

        # Clear ID for import
        if "id" in dash_obj:
            dash_obj["id"] = None

        import_payload = json.dumps({
            "dashboard": dash_obj,
            "overwrite": True,
            "inputs": [
                {
                    "name": "DS_PROMETHEUS",
                    "type": "datasource",
                    "pluginId": "prometheus",
                    "value": "Prometheus",
                }
            ],
            "folderId": 0,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{grafana_url}/api/dashboards/import",
            data=import_payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth_header}",
                "X-WEBAUTH-USER": "admin",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=30)
        return True, f"Dashboard '{EXPORTERS[name]['dashboard_name']}' imported"

    except Exception as e:
        return False, f"Dashboard import failed: {str(e)[:80]}"


def _remove_grafana_dashboard(name: str) -> tuple:
    """Remove a dashboard from Grafana by UID."""
    import urllib.request

    grafana_url, auth_header = _get_grafana_credentials()
    uid = EXPORTERS[name]["dashboard_uid"]

    try:
        req = urllib.request.Request(
            f"{grafana_url}/api/dashboards/uid/{uid}",
            headers={
                "Authorization": f"Basic {auth_header}",
                "X-WEBAUTH-USER": "admin",
            },
            method="DELETE",
        )
        urllib.request.urlopen(req, timeout=10)
        return True, f"Dashboard removed"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True, "Dashboard was already removed"
        return False, f"Failed to remove dashboard: HTTP {e.code}"
    except Exception as e:
        return False, f"Failed to remove dashboard: {str(e)[:80]}"
