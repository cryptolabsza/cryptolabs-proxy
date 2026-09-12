"""Contract tests for the optional Vast Price Manager Fleet integration."""

import importlib.util
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from multiprocessing import get_context
import os
from pathlib import Path
import threading

from click.testing import CliRunner
import pytest


REPOSITORY = Path(__file__).resolve().parents[1]


def _register_service_in_process(config_dir, service_name, ready, start, result_queue):
    """Run a real CLI registration in a separate process for lock coverage."""
    import cryptolabs_proxy.cli as cli

    cli.CONFIG_DIR = Path(config_dir)
    cli.check_root = lambda: None
    cli.proxy_uses_generated_config = lambda path: True
    cli.validate_nginx_config = lambda: (True, "")
    cli.reload_nginx_config = lambda: (True, "")
    ready.set()
    start.wait(5)
    result = CliRunner().invoke(
        cli.main,
        ["register", service_name, service_name, "--path", f"/{service_name}/", "--port", "9010"],
    )
    result_queue.put((result.exit_code, result.output))


def _register_service_after_rollback_lock(config_dir, entered, result_queue):
    """Attempt a real lifecycle command and mark only after its registry lock."""
    import cryptolabs_proxy.cli as cli

    cli.CONFIG_DIR = Path(config_dir)
    cli.check_root = lambda: None
    cli.proxy_uses_generated_config = lambda path: entered.set() or True
    cli.validate_nginx_config = lambda: (True, "")
    cli.reload_nginx_config = lambda: (True, "")
    result = CliRunner().invoke(
        cli.main,
        ["register", "service-after-rollback", "service-after-rollback", "--path", "/after/", "--port", "9011"],
    )
    result_queue.put((result.exit_code, result.output))


def load_health_api():
    """Load the standalone health API script without starting its server."""
    spec = importlib.util.spec_from_file_location(
        "health_api", REPOSITORY / "scripts" / "health-api.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vast_price_manager_registry_contract():
    from cryptolabs_proxy.services import DEFAULT_SERVICES

    service = DEFAULT_SERVICES["vast-price-manager"]
    assert service["container_name"] == "vast-price-manager"
    assert service["path"] == "/vast-pricing/"
    assert service["port"] == 8088
    assert service["display_name"] == "Vast Price Manager"
    assert service["product_url"] == "https://github.com/cryptolabsza/vast-price-manager"
    assert service["admin_only"] is True
    assert service["lifecycle_manager"] == "dc-overview"


def test_rendered_vpm_route_authorizes_session_admin_and_preserves_uri(tmp_path):
    from cryptolabs_proxy.config import generate_nginx_config
    from cryptolabs_proxy.services import DEFAULT_SERVICES

    generate_nginx_config(tmp_path, "fleet.example.test", services={})
    config = (tmp_path / "nginx.conf").read_text()

    assert "location = /vast-pricing {" not in config
    assert 'location = /auth/vast-price-manager/session { return 404; }' in config
    assert 'location = /auth/vast-price-manager/reauth { return 404; }' in config

    generate_nginx_config(
        tmp_path,
        "fleet.example.test",
        services={"vast-price-manager": deepcopy(DEFAULT_SERVICES["vast-price-manager"])},
    )
    config = (tmp_path / "nginx.conf").read_text()

    assert "location = /vast-pricing {" in config
    assert "return 308 /vast-pricing/;" in config
    assert "location = /_vast_pricing_admin {" in config
    assert "proxy_pass http://127.0.0.1:8081/auth/vast-price-manager/authorize;" in config
    assert "location ~ ^/vast-pricing(?<vpm_upstream_path>/.*)$ {" in config
    vpm_route = config.split("location ~ ^/vast-pricing(?<vpm_upstream_path>/.*)$ {")[1].split("\n        }", 1)[0]
    assert "auth_request /_vast_pricing_admin;" in vpm_route
    assert "proxy_pass http://$upstream_vast_price_manager:8088$vpm_upstream_path$is_args$args;" in vpm_route
    assert "proxy_set_header X-Forwarded-Host $host;" in vpm_route
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in vpm_route
    assert 'proxy_set_header X-Fleet-Auth-Role "";' in vpm_route
    assert 'location = /auth/vast-price-manager/session { return 404; }' in config
    assert 'location = /auth/vast-price-manager/session/ { return 404; }' in config
    assert 'location = /auth/vast-price-manager/reauth { return 404; }' in config
    assert 'location = /auth/vast-price-manager/reauth/ { return 404; }' in config
    assert 'proxy_set_header Cookie $http_cookie;' in vpm_route
    assert 'proxy_intercept_errors off;' in vpm_route
    assert 'error_page 502 503 504 = @service_unavailable;' in vpm_route


def test_cli_register_unregister_toggles_generated_vpm_route_and_preserves_metadata(monkeypatch, tmp_path):
    import cryptolabs_proxy.cli as cli
    from cryptolabs_proxy.services import ServiceRegistry

    monkeypatch.setattr(cli, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cli, "check_root", lambda: None)
    monkeypatch.setattr(cli, "proxy_uses_generated_config", lambda path: True)
    monkeypatch.setattr(cli, "validate_nginx_config", lambda: (True, ""))
    monkeypatch.setattr(cli, "reload_nginx_config", lambda: (True, ""))

    original = ServiceRegistry(tmp_path)
    original.config = {"domain": "fleet.example.test", "letsencrypt": False, "keep": "setting"}
    original.add_service("existing-service", "existing-service", "/existing/", 9010, description="keep me")

    runner = CliRunner()
    register = runner.invoke(
        cli.main,
        ["register", "vast-price-manager", "vast-price-manager", "--path", "/vast-pricing/", "--port", "8088"],
    )
    assert register.exit_code == 0, register.output

    registry = ServiceRegistry(tmp_path)
    service = registry.get_service("vast-price-manager")
    assert service["lifecycle_manager"] == "dc-overview"
    assert service["admin_only"] is True
    assert "location = /vast-pricing {" in (tmp_path / "nginx.conf").read_text()
    assert registry.get_service("existing-service")["description"] == "keep me"
    assert registry.config["keep"] == "setting"

    unregister = runner.invoke(cli.main, ["unregister", "vast-price-manager"])
    assert unregister.exit_code == 0, unregister.output
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager") is None
    assert "location = /vast-pricing {" not in (tmp_path / "nginx.conf").read_text()
    assert ServiceRegistry(tmp_path).get_service("existing-service")["path"] == "/existing/"
    assert ServiceRegistry(tmp_path).config["keep"] == "setting"

    reregister = runner.invoke(
        cli.main,
        ["register", "vast-price-manager", "vast-price-manager", "--path", "/vast-pricing/", "--port", "8088"],
    )
    assert reregister.exit_code == 0, reregister.output
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager")["lifecycle_manager"] == "dc-overview"
    assert "location = /vast-pricing {" in (tmp_path / "nginx.conf").read_text()


def test_cli_unregister_rolls_back_registry_and_generated_config_when_reload_fails(monkeypatch, tmp_path):
    import cryptolabs_proxy.cli as cli
    from cryptolabs_proxy.config import generate_nginx_config
    from cryptolabs_proxy.services import DEFAULT_SERVICES, ServiceRegistry

    registry = ServiceRegistry(tmp_path)
    registry.config = {"domain": "fleet.example.test", "letsencrypt": False, "keep": "setting"}
    registry.services = {"vast-price-manager": deepcopy(DEFAULT_SERVICES["vast-price-manager"])}
    registry.save()
    generate_nginx_config(tmp_path, "fleet.example.test", services=registry.services)
    previous_registry = registry.services_file.read_text()
    previous_config = (tmp_path / "nginx.conf").read_text()

    monkeypatch.setattr(cli, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cli, "check_root", lambda: None)
    monkeypatch.setattr(cli, "proxy_uses_generated_config", lambda path: True)
    monkeypatch.setattr(cli, "validate_nginx_config", lambda: (True, ""))
    reload_calls = []
    monkeypatch.setattr(cli, "reload_nginx_config", lambda: reload_calls.append(True) or (False, "reload failed"))

    result = CliRunner().invoke(cli.main, ["unregister", "vast-price-manager"])

    assert result.exit_code != 0
    assert "reload failed" in result.output
    assert registry.services_file.read_text() == previous_registry
    assert (tmp_path / "nginx.conf").read_text() == previous_config
    assert "location = /vast-pricing {" in (tmp_path / "nginx.conf").read_text()
    assert len(reload_calls) == 2


def test_default_nginx_config_has_no_vpm_route_before_generated_config_migration():
    config = (REPOSITORY / "nginx" / "nginx.conf").read_text()

    assert "location = /vast-pricing {" not in config
    assert "location = /_vast_pricing_admin {" not in config
    assert "location ~ ^/vast-pricing(?<vpm_upstream_path>/.*)$ {" not in config


def test_concurrent_cli_registrations_preserve_both_services(tmp_path):
    context = get_context("fork")
    start = context.Event()
    first_ready = context.Event()
    second_ready = context.Event()
    result_queue = context.Queue()
    first = context.Process(
        target=_register_service_in_process,
        args=(str(tmp_path), "service-one", first_ready, start, result_queue),
    )
    second = context.Process(
        target=_register_service_in_process,
        args=(str(tmp_path), "service-two", second_ready, start, result_queue),
    )
    first.start()
    second.start()
    assert first_ready.wait(5)
    assert second_ready.wait(5)
    start.set()
    first.join(10)
    second.join(10)

    assert first.exitcode == 0
    assert second.exitcode == 0
    assert [result_queue.get(timeout=2)[0] for _ in range(2)] == [0, 0]

    from cryptolabs_proxy.services import ServiceRegistry

    assert set(ServiceRegistry(tmp_path).services) == {"service-one", "service-two"}


def test_vpm_admin_authorization_is_session_backed_not_header_backed(client, admin_user):
    anonymous = client.get("/auth/vast-price-manager/authorize")
    assert anonymous.status_code == 401

    forged = client.get(
        "/auth/vast-price-manager/authorize",
        headers={"X-Fleet-Auth-Role": "admin", "X-Fleet-Auth-User": "forged"},
    )
    assert forged.status_code == 401

    client.post("/auth/login", data={"username": admin_user["username"], "password": admin_user["password"]})
    admin = client.get("/auth/vast-price-manager/authorize")
    assert admin.status_code == 204


def test_vpm_admin_authorization_rejects_readonly_and_readwrite(client, readonly_user, readwrite_user):
    for user in (readonly_user, readwrite_user):
        client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
        response = client.get("/auth/vast-price-manager/authorize")
        assert response.status_code == 403
        client.get("/auth/logout")


def test_vpm_health_status_distinguishes_unconfigured_from_healthy(monkeypatch):
    health_api = load_health_api()
    monkeypatch.setattr(health_api, "check_container_running", lambda name: name == "vast-price-manager")
    monkeypatch.setattr(health_api, "get_vast_price_manager_readiness", lambda: "unconfigured")
    monkeypatch.setattr(health_api, "get_vast_price_manager_docker_health", lambda: "healthy")

    status = health_api.get_all_service_status()["vast-price-manager"]

    assert status["running"] is True
    assert status["healthy"] is True
    assert status["state"] == "unconfigured"
    assert status["configured"] is False
    assert status["lifecycle_manager"] == "dc-overview"


def test_vpm_health_does_not_treat_a_running_unhealthy_container_as_healthy(monkeypatch):
    health_api = load_health_api()
    monkeypatch.setattr(health_api, "check_container_running", lambda name: name == "vast-price-manager")
    monkeypatch.setattr(health_api, "get_vast_price_manager_readiness", lambda: "ready")
    monkeypatch.setattr(health_api, "get_vast_price_manager_docker_health", lambda: "unhealthy")

    status = health_api.get_all_service_status()["vast-price-manager"]

    assert status["running"] is True
    assert status["healthy"] is False
    assert status["docker_health"] == "unhealthy"
    assert status["configured"] is True


def test_vpm_allowed_host_reads_only_the_nonsecret_container_setting(monkeypatch):
    health_api = load_health_api()

    class Result:
        returncode = 0
        stdout = "VPM_ALLOWED_HOSTS=fleet.example.test, alternative.example.test\nVPM_MASTER_KEY=not-read\n"

    monkeypatch.setattr(health_api.subprocess, "run", lambda *args, **kwargs: Result())

    assert health_api.get_vast_price_manager_allowed_host() == "fleet.example.test"


@pytest.mark.skipif(
    os.environ.get("PROXY_NETWORK_TEST") != "1",
    reason="requires a local HTTP listener for probe transport verification",
)
def test_vpm_readiness_probe_uses_allowed_public_host_over_http_transport(monkeypatch):
    observed = {}

    class VpmReadinessHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed["path"] = self.path
            observed["host"] = self.headers.get("Host")
            self.send_response(503 if observed["host"] == "fleet.example.test" else 400)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), VpmReadinessHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        health_api = load_health_api()
        monkeypatch.setattr(health_api, "VPM_READY_URL", f"http://127.0.0.1:{server.server_port}/readyz", raising=False)
        monkeypatch.setattr(health_api, "get_vast_price_manager_allowed_host", lambda: "fleet.example.test", raising=False)

        assert health_api.get_vast_price_manager_readiness() == "unconfigured"
        assert observed == {"path": "/readyz", "host": "fleet.example.test"}
    finally:
        server.shutdown()
        thread.join()


def test_vpm_lifecycle_actions_are_rejected_by_generic_update_api():
    health_api = load_health_api()
    assert health_api.service_action_error("vast-price-manager") == (
        "Vast Price Manager lifecycle is managed by dc-overview."
    )


CUSTOM_PROXY_CONFIG = b'''worker_processes auto;
events { worker_connections 1024; }
http {
    upstream auth_server { server 127.0.0.1:8081; }
    server { listen 80; location /legacy/ { proxy_pass http://legacy; } }
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        location @service_unavailable { return 503; }
        location @login_redirect {
            return 302 /auth/login?next=$request_uri;
        }
        location /auth/ { proxy_pass http://auth_server/auth/; }
        location /unrelated/ { default_type application/json; return 200 '{"keep":"bytes"}'; }
    }
    server { listen 8080; location /health { return 200; } }
}
'''


def test_custom_config_render_preserves_baseline_bytes_and_uses_canonical_fragment(tmp_path):
    from cryptolabs_proxy.custom_config import render_managed_vpm_config
    from cryptolabs_proxy.config import render_vpm_fragment, render_vpm_internal_auth_blocks

    rendered = render_managed_vpm_config(CUSTOM_PROXY_CONFIG, enabled=True)
    auth_denies = render_vpm_internal_auth_blocks().encode().rstrip()
    managed_auth_block = (
        b"\n# BEGIN CRYPTOLABS MANAGED INTERNAL AUTH DENIES\n"
        + auth_denies
        + b"\n# END CRYPTOLABS MANAGED INTERNAL AUTH DENIES\n"
    )
    managed_vpm_block = (
        b"# BEGIN CRYPTOLABS MANAGED VPM\n"
        + render_vpm_fragment().encode().rstrip()
        + b"\n# END CRYPTOLABS MANAGED VPM\n"
    )

    assert b'# BEGIN CRYPTOLABS MANAGED VPM' in rendered
    assert render_vpm_fragment().encode() in rendered
    assert rendered.count(b'# BEGIN CRYPTOLABS MANAGED INTERNAL AUTH DENIES') == 3
    assert rendered.replace(managed_vpm_block, b'').replace(managed_auth_block, b'') == CUSTOM_PROXY_CONFIG
    assert b'location /unrelated/ { default_type application/json; return 200 \'{"keep":"bytes"}\'; }' in rendered
    assert b'location = /auth/vast-price-manager/session { return 404; }' in rendered
    assert b'location = /auth/vast-price-manager/session/ { return 404; }' in rendered
    assert b'location = /auth/vast-price-manager/reauth { return 404; }' in rendered
    assert b'location = /auth/vast-price-manager/reauth/ { return 404; }' in rendered
    disabled = render_managed_vpm_config(CUSTOM_PROXY_CONFIG, enabled=False)
    assert b'# BEGIN CRYPTOLABS MANAGED VPM' not in disabled
    assert b'location = /auth/vast-price-manager/session { return 404; }' in disabled
    assert b'location = /auth/vast-price-manager/session/ { return 404; }' in disabled
    assert b'location = /auth/vast-price-manager/reauth { return 404; }' in disabled
    assert b'location = /auth/vast-price-manager/reauth/ { return 404; }' in disabled
    assert b'location = /vast-pricing {' not in disabled
    assert b'proxy_pass http://$upstream_vast_price_manager:8088' not in disabled
    assert disabled.count(b'# BEGIN CRYPTOLABS MANAGED INTERNAL AUTH DENIES') == 3
    assert disabled.replace(managed_auth_block, b'') == CUSTOM_PROXY_CONFIG


def test_custom_config_blocks_internal_vpm_auth_in_each_http_server_block():
    from cryptolabs_proxy.custom_config import render_managed_vpm_config

    multi_server_baseline = CUSTOM_PROXY_CONFIG.replace(
        b"server { listen 80; location /legacy/ { proxy_pass http://legacy; } }",
        b"server { listen 80; location /auth/ { proxy_pass http://auth_server/auth/; } location /legacy/ { proxy_pass http://legacy; } }",
    )

    disabled = render_managed_vpm_config(multi_server_baseline, enabled=False)

    assert b"location /auth/ { proxy_pass http://auth_server/auth/; }" in disabled
    assert disabled.count(b"location = /auth/vast-price-manager/session { return 404; }") == 3
    assert disabled.count(b"location = /auth/vast-price-manager/reauth { return 404; }") == 3
    assert b"proxy_pass http://$upstream_vast_price_manager:8088" not in disabled


@pytest.mark.parametrize(
    "baseline, expected",
    [
        (CUSTOM_PROXY_CONFIG.replace(b"location @login_redirect", b"location @not_login_redirect"), "exactly one"),
        (CUSTOM_PROXY_CONFIG.replace(b"location @login_redirect", b"location @login_redirect", 1) + b"\nlocation @login_redirect { return 302 /; }\n", "exactly one"),
        (CUSTOM_PROXY_CONFIG + b"# BEGIN CRYPTOLABS MANAGED VPM\n", "managed VPM"),
        (CUSTOM_PROXY_CONFIG.replace(b"location @service_unavailable", b"location @not_service_unavailable"), "required Fleet auth"),
    ],
)
def test_custom_config_render_rejects_missing_duplicate_or_previously_managed_anchors(baseline, expected):
    from cryptolabs_proxy.custom_config import CustomConfigError, render_managed_vpm_config

    with pytest.raises(CustomConfigError, match=expected):
        render_managed_vpm_config(baseline, enabled=True)


def test_cli_vpm_lifecycle_preserves_custom_baseline_and_rejects_unrelated_routes(monkeypatch, tmp_path):
    import cryptolabs_proxy.cli as cli
    from cryptolabs_proxy.custom_config import configure_custom_config_mode
    from cryptolabs_proxy.services import ServiceRegistry

    baseline_path = tmp_path / "baselines" / "proxy.conf"
    baseline_path.parent.mkdir()
    baseline_path.write_bytes(CUSTOM_PROXY_CONFIG)
    registry = ServiceRegistry(tmp_path)
    registry.services = {"existing-service": {"container_name": "existing", "path": "/existing/", "port": 9000}}
    configure_custom_config_mode(registry.config, baseline_path)
    registry.save()

    monkeypatch.setattr(cli, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cli, "check_root", lambda: None)
    monkeypatch.setattr(cli, "proxy_uses_generated_config", lambda path: True)
    monkeypatch.setattr(cli, "validate_nginx_config", lambda: (True, ""))
    monkeypatch.setattr(cli, "reload_nginx_config", lambda: (True, ""))
    runner = CliRunner()

    enabled = runner.invoke(cli.main, ["register", "vast-price-manager", "vast-price-manager", "--path", "/vast-pricing/", "--port", "8088"])
    assert enabled.exit_code == 0, enabled.output
    candidate = (tmp_path / "nginx.conf").read_bytes()
    assert b"location /unrelated/" in candidate
    assert b"# BEGIN CRYPTOLABS MANAGED VPM" in candidate
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager")["path"] == "/vast-pricing/"
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager")["port"] == 8088
    assert ServiceRegistry(tmp_path).get_service("existing-service")["path"] == "/existing/"

    rejected = runner.invoke(cli.main, ["register", "unrelated-service", "unrelated", "--path", "/unrelated-new/", "--port", "9001"])
    assert rejected.exit_code != 0
    assert "custom-config mode permits only vast-price-manager" in rejected.output
    assert (tmp_path / "nginx.conf").read_bytes() == candidate

    disabled = runner.invoke(cli.main, ["unregister", "vast-price-manager"])
    assert disabled.exit_code == 0, disabled.output
    disabled_config = (tmp_path / "nginx.conf").read_bytes()
    assert b"location /unrelated/" in disabled_config
    assert b"# BEGIN CRYPTOLABS MANAGED VPM" not in disabled_config
    assert b"location = /auth/vast-price-manager/session { return 404; }" in disabled_config
    assert b"location = /auth/vast-price-manager/session/ { return 404; }" in disabled_config
    assert b"location = /auth/vast-price-manager/reauth { return 404; }" in disabled_config
    assert b"location = /auth/vast-price-manager/reauth/ { return 404; }" in disabled_config
    assert b"location = /vast-pricing {" not in disabled_config
    assert b"proxy_pass http://$upstream_vast_price_manager:8088" not in disabled_config
    assert ServiceRegistry(tmp_path).config["custom_config"]["baseline_sha256"] == hashlib.sha256(CUSTOM_PROXY_CONFIG).hexdigest()

    reenabled = runner.invoke(cli.main, ["register", "vast-price-manager", "vast-price-manager", "--path", "/vast-pricing/", "--port", "8088"])
    assert reenabled.exit_code == 0, reenabled.output
    reenabled_config = (tmp_path / "nginx.conf").read_bytes()
    assert reenabled_config.count(b"# BEGIN CRYPTOLABS MANAGED INTERNAL AUTH DENIES") == 3
    assert reenabled_config.count(b"# BEGIN CRYPTOLABS MANAGED VPM") == 1

    disabled_again = runner.invoke(cli.main, ["unregister", "vast-price-manager"])
    assert disabled_again.exit_code == 0, disabled_again.output
    disabled_again_config = (tmp_path / "nginx.conf").read_bytes()
    assert disabled_again_config.count(b"# BEGIN CRYPTOLABS MANAGED INTERNAL AUTH DENIES") == 3
    assert b"# BEGIN CRYPTOLABS MANAGED VPM" not in disabled_again_config


def test_custom_mode_refuses_changed_baseline_before_mutating_registry(monkeypatch, tmp_path):
    import cryptolabs_proxy.cli as cli
    from cryptolabs_proxy.custom_config import configure_custom_config_mode
    from cryptolabs_proxy.services import ServiceRegistry

    baseline_path = tmp_path / "baseline.conf"
    baseline_path.write_bytes(CUSTOM_PROXY_CONFIG)
    registry = ServiceRegistry(tmp_path)
    configure_custom_config_mode(registry.config, baseline_path)
    registry.save()
    baseline_path.write_bytes(CUSTOM_PROXY_CONFIG + b"# changed")

    monkeypatch.setattr(cli, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cli, "check_root", lambda: None)
    result = CliRunner().invoke(cli.main, ["register", "vast-price-manager", "vast-price-manager", "--path", "/vast-pricing/", "--port", "8088"])

    assert result.exit_code != 0
    assert "baseline SHA-256 changed" in result.output
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager") is None


def test_engine_clone_preserves_full_settings_and_adds_only_candidate_config_mount():
    from cryptolabs_proxy.migration import build_recreate_request

    inspect = {
        "Config": {"Image": "old@sha256:old", "Env": ["SECRET=not-printed"], "Labels": {"keep": "label"}, "Cmd": ["nginx"]},
        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "PortBindings": {"443/tcp": [{"HostPort": "443"}]}, "LogConfig": {"Type": "json-file"}, "Binds": []},
        "Mounts": [
            {"Type": "volume", "Name": "fleet-auth-data", "Source": "/var/lib/docker/volumes/fleet-auth-data/_data", "Destination": "/data/auth", "RW": True},
            {"Type": "bind", "Source": "/etc/cryptolabs-proxy/ssl", "Destination": "/etc/nginx/ssl", "RW": False},
        ],
        "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["cryptolabs-proxy"], "DriverOpts": {"keep": "value"}, "EndpointID": "engine-assigned", "IPAddress": "172.30.0.2"}}},
    }

    request = build_recreate_request(inspect, "new@sha256:reviewed", "/etc/cryptolabs-proxy/nginx.conf")

    assert request["Config"]["Image"] == "new@sha256:reviewed"
    assert request["Config"]["Env"] == inspect["Config"]["Env"]
    assert request["Config"]["Labels"] == inspect["Config"]["Labels"]
    assert request["HostConfig"]["RestartPolicy"] == inspect["HostConfig"]["RestartPolicy"]
    assert request["HostConfig"]["PortBindings"] == inspect["HostConfig"]["PortBindings"]
    assert request["HostConfig"]["LogConfig"] == inspect["HostConfig"]["LogConfig"]
    assert request["NetworkingConfig"]["EndpointsConfig"]["cryptolabs"]["Aliases"] == ["cryptolabs-proxy"]
    assert "EndpointID" not in request["NetworkingConfig"]["EndpointsConfig"]["cryptolabs"]
    assert "IPAddress" not in request["NetworkingConfig"]["EndpointsConfig"]["cryptolabs"]
    mounts = request["HostConfig"]["Mounts"]
    assert any(m["Type"] == "volume" and m["Source"] == "fleet-auth-data" and m["Target"] == "/data/auth" for m in mounts)
    assert any(m["Type"] == "bind" and m["Source"] == "/etc/cryptolabs-proxy/nginx.conf" and m["Target"] == "/etc/nginx/nginx.conf" and m["ReadOnly"] is True for m in mounts)


@pytest.mark.parametrize("failure", ["stop", "rename", "create", "start", "health"])
def test_switch_controller_compensates_each_failed_proxy_swap(failure):
    from cryptolabs_proxy.migration import MigrationError, SwitchController

    class Engine:
        def __init__(self):
            self.calls = []
            self.failed_candidate_start = False

        def stop(self, name, ignore_missing=False):
            self.calls.append(("stop", name, ignore_missing))
            if failure == "stop" and name == "cryptolabs-proxy":
                raise RuntimeError("stop failed")

        def rename(self, old, new):
            self.calls.append(("rename", old, new))
            if failure == "rename" and old == "cryptolabs-proxy":
                raise RuntimeError("rename failed")

        def create(self, name, request):
            self.calls.append(("create", name))
            if failure == "create":
                raise RuntimeError("create failed")

        def start(self, name):
            self.calls.append(("start", name))
            if failure == "start" and name == "cryptolabs-proxy" and not self.failed_candidate_start:
                self.failed_candidate_start = True
                raise RuntimeError("start failed")

        def remove(self, name, ignore_missing=False):
            self.calls.append(("remove", name, ignore_missing))

        def disconnect(self, name, network):
            self.calls.append(("disconnect", name, network))

        def connect(self, name, network, endpoint):
            self.calls.append(("connect", name, network, endpoint))

    engine = Engine()
    controller = SwitchController(engine, health_check=lambda name: failure != "health")

    with pytest.raises(MigrationError):
        controller.apply("cryptolabs-proxy", "test", {"candidate": True, "NetworkingConfig": {"EndpointsConfig": {}}})

    if failure == "stop":
        assert engine.calls == [("stop", "cryptolabs-proxy", False)]
    else:
        assert ("start", "cryptolabs-proxy") in engine.calls
        if failure in {"create", "start", "health"}:
            assert ("rename", "cryptolabs-proxy.rollback-test", "cryptolabs-proxy") in engine.calls
        if failure == "start":
            assert ("remove", "cryptolabs-proxy.candidate-test", True) in engine.calls
        if failure == "health":
            assert ("remove", "cryptolabs-proxy.candidate-test", True) not in engine.calls


def test_migration_plan_is_deterministic_and_exposes_no_environment_data():
    from cryptolabs_proxy.migration import MigrationPlan

    plan = MigrationPlan.from_source("container-id", CUSTOM_PROXY_CONFIG, "proxy@sha256:reviewed")
    manifest = plan.sanitized_manifest()

    assert manifest["migration_id"] == MigrationPlan.from_source("container-id", CUSTOM_PROXY_CONFIG, "proxy@sha256:reviewed").migration_id
    assert manifest["baseline_sha256"] == hashlib.sha256(CUSTOM_PROXY_CONFIG).hexdigest()
    assert "Env" not in manifest


def test_candidate_validation_uses_nginx_entrypoint_and_always_removes_owned_container(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationError

    commands = []

    class Result:
        returncode = 0

    def run(command, **kwargs):
        commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return Result()
        return Result()

    monkeypatch.setattr("cryptolabs_proxy.migration.subprocess.run", run)
    candidate = tmp_path / "nginx.conf"
    candidate.write_bytes(CUSTOM_PROXY_CONFIG)
    inspect = {"Mounts": [{"Destination": "/etc/nginx/ssl", "Source": "/ssl"}]}

    CustomConfigMigrator(tmp_path, tmp_path / "backups")._validate_candidate("proxy@sha256:reviewed", candidate, inspect, "migration-id")

    validation = commands[0]
    assert validation[:3] == ["docker", "run", "--name"]
    assert "--entrypoint" in validation
    assert validation[validation.index("--entrypoint") + 1] == "nginx"
    assert "--label" in validation
    assert validation[-1:] == ["-t"]
    assert commands[-1][:3] == ["docker", "rm", "-f"]


def test_candidate_validation_cleans_owned_container_when_nginx_fails(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationError

    commands = []

    class Result:
        def __init__(self, returncode):
            self.returncode = returncode

    def run(command, **kwargs):
        commands.append(command)
        return Result(1 if command[:2] == ["docker", "run"] else 0)

    monkeypatch.setattr("cryptolabs_proxy.migration.subprocess.run", run)
    candidate = tmp_path / "nginx.conf"
    candidate.write_bytes(CUSTOM_PROXY_CONFIG)
    inspect = {"Mounts": [{"Destination": "/etc/nginx/ssl", "Source": "/ssl"}]}

    with pytest.raises(MigrationError, match="validation failed"):
        CustomConfigMigrator(tmp_path, tmp_path / "backups")._validate_candidate("proxy@sha256:reviewed", candidate, inspect, "migration-id")

    assert commands[-1][:3] == ["docker", "rm", "-f"]


def test_engine_clone_preserves_static_ip_and_rejects_tmpfs_mounts():
    from cryptolabs_proxy.migration import MigrationError, build_recreate_request

    inspect = {
        "Config": {"Image": "old", "Env": ["SECRET=redacted"]},
        "HostConfig": {"PortBindings": {"80/tcp": [{"HostPort": "80"}]}},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["stable-alias"], "IPAMConfig": {"IPv4Address": "172.30.0.10"}}}},
    }
    request = build_recreate_request(inspect, "new@sha256:reviewed", "/candidate.conf")
    endpoint = request["NetworkingConfig"]["EndpointsConfig"]["cryptolabs"]
    assert endpoint["Aliases"] == ["stable-alias"]
    assert endpoint["IPAMConfig"] == {"IPv4Address": "172.30.0.10"}
    assert request["HostConfig"]["PortBindings"] == inspect["HostConfig"]["PortBindings"]

    inspect["Mounts"] = [{"Type": "tmpfs", "Destination": "/run/cache", "RW": True}]
    with pytest.raises(MigrationError, match="unsupported mount type"):
        build_recreate_request(inspect, "new@sha256:reviewed", "/candidate.conf")


def test_startup_waits_through_starting_then_requires_unauthenticated_auth_401():
    from cryptolabs_proxy.migration import wait_for_proxy_ready

    states = iter([
        {"Running": True, "Health": {"Status": "starting"}},
        {"Running": True, "Health": {"Status": "healthy"}},
    ])

    class Engine:
        def inspect(self, container):
            return {"State": next(states)}

    probes = []
    ready = wait_for_proxy_ready(
        Engine(),
        "candidate",
        auth_probe=lambda: probes.append(True) or True,
        timeout=2,
        interval=0,
    )

    assert ready is True
    assert probes == [True]


def test_startup_rejects_healthy_proxy_when_unauthenticated_auth_does_not_return_401():
    from cryptolabs_proxy.migration import wait_for_proxy_ready

    class Engine:
        def inspect(self, container):
            return {"State": {"Running": True, "Health": {"Status": "healthy"}}}

    assert wait_for_proxy_ready(Engine(), "candidate", auth_probe=lambda: False, timeout=0, interval=0) is False


def test_manual_rollback_keeps_and_restores_candidate_when_old_proxy_is_unhealthy(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationError

    migration_id = "migration"
    backup = tmp_path / "backups" / migration_id
    backup.mkdir(parents=True)
    source = {"Id": "old-id", "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["old"], "IPAMConfig": {"IPv4Address": "172.30.0.10"}}}}}
    (backup / "inspect.json").write_text(__import__("json").dumps(source))
    (backup / "registry-snapshot.json").write_text("{}")

    class Engine:
        def __init__(self):
            self.calls = []

        def inspect(self, name):
            if name == "cryptolabs-proxy.rollback-migration":
                return source
            return {"Id": "candidate-id", "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["candidate"], "IPAMConfig": {"IPv4Address": "172.30.0.10"}}}}}

        def stop(self, *args, **kwargs): self.calls.append(("stop", args[0]))
        def disconnect(self, *args): self.calls.append(("disconnect", args[0], args[1]))
        def rename(self, *args): self.calls.append(("rename", *args))
        def connect(self, *args): self.calls.append(("connect", args[0], args[1]))
        def start(self, *args): self.calls.append(("start", args[0]))
        def remove(self, *args, **kwargs): self.calls.append(("remove", args[0]))

    monkeypatch.setattr("cryptolabs_proxy.migration.os.geteuid", lambda: 0)
    monkeypatch.setattr("cryptolabs_proxy.migration.wait_for_proxy_ready", lambda *args: True)
    monkeypatch.setattr("cryptolabs_proxy.migration.wait_for_container_healthy", lambda *args: False)
    engine = Engine()

    with pytest.raises(MigrationError, match="healthy replacement was restored"):
        CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=engine).rollback("cryptolabs-proxy", migration_id)

    assert ("rename", "cryptolabs-proxy", "cryptolabs-proxy.candidate-migration") in engine.calls
    assert ("rename", "cryptolabs-proxy.candidate-migration", "cryptolabs-proxy") in engine.calls
    assert not any(call[0] == "remove" for call in engine.calls)


@pytest.mark.parametrize("failure", ["disconnect-second", "rename"])
def test_switch_controller_reconnects_only_detached_source_endpoints_before_restart(failure):
    from cryptolabs_proxy.migration import MigrationError, SwitchController

    endpoints = {
        "cryptolabs": {"Aliases": ["proxy"], "IPAMConfig": {"IPv4Address": "172.30.0.10"}},
        "monitoring": {"Aliases": ["metrics"]},
    }

    class Engine:
        def __init__(self):
            self.calls = []

        def stop(self, name, ignore_missing=False): self.calls.append(("stop", name))
        def start(self, name): self.calls.append(("start", name))
        def disconnect(self, name, network):
            self.calls.append(("disconnect", name, network))
            if failure == "disconnect-second" and network == "monitoring":
                raise RuntimeError("second disconnect failed")
        def rename(self, old, new):
            self.calls.append(("rename", old, new))
            if failure == "rename":
                raise RuntimeError("rename failed")
        def create(self, *args): raise AssertionError("candidate must not be created")
        def connect(self, name, network, endpoint): self.calls.append(("connect", name, network, endpoint))

    engine = Engine()
    with pytest.raises(MigrationError):
        SwitchController(engine, health_check=lambda _: True).apply(
            "source-id", "repair", {"NetworkingConfig": {"EndpointsConfig": endpoints}}, "cryptolabs-proxy"
        )

    reconnects = [call for call in engine.calls if call[0] == "connect"]
    expected_networks = ["cryptolabs"] if failure == "disconnect-second" else ["cryptolabs", "monitoring"]
    assert [call[2] for call in reconnects] == expected_networks
    assert [call[3] for call in reconnects] == [endpoints[network] for network in expected_networks]
    assert engine.calls[-1] == ("start", "source-id")


def test_readiness_budget_exceeds_image_health_cadence_and_transport_timeout_is_separate(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import (
        CustomConfigMigrator,
        PROXY_READY_TIMEOUT,
        wait_for_proxy_ready,
    )

    assert PROXY_READY_TIMEOUT >= 110  # Docker start period + three intervals + probe allowance.
    now = [0.0]

    class Engine:
        def __init__(self):
            self.states = iter([
                {"Running": True, "Health": {"Status": "starting"}},
                {"Running": True, "Health": {"Status": "starting"}},
                {"Running": True, "Health": {"Status": "healthy"}},
            ])

        def inspect(self, container):
            return {"State": next(self.states)}

    monkeypatch.setattr("cryptolabs_proxy.migration.time.monotonic", lambda: now[0])
    monkeypatch.setattr("cryptolabs_proxy.migration.time.sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    assert wait_for_proxy_ready(Engine(), "candidate", lambda: True, timeout=PROXY_READY_TIMEOUT, interval=16) is True

    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", timeout=7)
    assert migrator.engine.timeout == 7
    assert migrator.readiness_timeout == PROXY_READY_TIMEOUT
    with pytest.raises(Exception, match="readiness timeout must be at least"):
        CustomConfigMigrator(tmp_path, tmp_path / "backups", readiness_timeout=15)


def test_apply_uses_engine_health_polling_with_the_real_switch_controller(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationPlan

    image = "proxy@sha256:reviewed"
    source = {
        "Id": "source-id",
        "Config": {"Image": "old"},
        "HostConfig": {"Binds": []},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["proxy"], "IPAMConfig": {"IPv4Address": "172.30.0.10"}}}},
    }

    class Engine:
        def __init__(self):
            self.calls = []
            self.inspect_calls = []

        def inspect(self, name):
            self.inspect_calls.append(name)
            if name == "cryptolabs-proxy" and self.inspect_calls.count(name) > 1:
                return {"State": {"Running": True, "Health": {"Status": "healthy"}}}
            return source

        def stop(self, name, ignore_missing=False): self.calls.append(("stop", name))
        def disconnect(self, name, network): self.calls.append(("disconnect", name, network))
        def rename(self, old, new): self.calls.append(("rename", old, new))
        def create(self, name, request): self.calls.append(("create", name, request))
        def start(self, name): self.calls.append(("start", name))
        def connect(self, name, network, endpoint): self.calls.append(("connect", name, network, endpoint))
        def remove(self, name, ignore_missing=False): self.calls.append(("remove", name))

    engine = Engine()
    plan = MigrationPlan.from_source("source-id", CUSTOM_PROXY_CONFIG, image)
    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=engine)
    monkeypatch.setattr("cryptolabs_proxy.migration.os.geteuid", lambda: 0)
    monkeypatch.setattr(migrator, "plan", lambda *args: plan)
    monkeypatch.setattr(migrator, "_read_active_config", lambda *args: CUSTOM_PROXY_CONFIG)
    monkeypatch.setattr(migrator, "_validate_candidate", lambda *args: None)
    monkeypatch.setattr(migrator, "_anonymous_auth_is_rejected", lambda: True)

    outcome = migrator.apply("cryptolabs-proxy", image, plan.migration_id, enable_vpm=True)

    assert outcome.state == "applied"
    assert any(call[:2] == ("create", "cryptolabs-proxy") for call in engine.calls)
    assert "cryptolabs-proxy" in engine.inspect_calls


def test_apply_retains_registry_and_candidate_config_for_recovered_candidate(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationOutcome, MigrationPlan, SwitchController
    from cryptolabs_proxy.services import ServiceRegistry

    image = "proxy@sha256:reviewed"
    source = {
        "Id": "source-id",
        "Config": {"Image": "old"},
        "HostConfig": {"Binds": []},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["proxy"], "IPAMConfig": {"IPv4Address": "172.30.0.10"}}}},
    }

    class Engine:
        def inspect(self, container): return source

    plan = MigrationPlan.from_source("source-id", CUSTOM_PROXY_CONFIG, image)
    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=Engine())
    (tmp_path / "nginx.conf").write_bytes(b"old candidate file")
    monkeypatch.setattr("cryptolabs_proxy.migration.os.geteuid", lambda: 0)
    monkeypatch.setattr(migrator, "plan", lambda *args: plan)
    monkeypatch.setattr(migrator, "_read_active_config", lambda *args: CUSTOM_PROXY_CONFIG)
    monkeypatch.setattr(migrator, "_validate_candidate", lambda *args: None)
    monkeypatch.setattr(
        SwitchController,
        "apply",
        lambda *args, **kwargs: MigrationOutcome.candidate_retained("old proxy restoration was unhealthy"),
    )

    outcome = migrator.apply("cryptolabs-proxy", image, plan.migration_id, enable_vpm=True)

    assert outcome.state == "candidate_retained"
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager") is not None
    assert b"BEGIN CRYPTOLABS MANAGED VPM" in (tmp_path / "nginx.conf").read_bytes()
    marker = tmp_path / "backups" / plan.migration_id / "outcome.json"
    assert marker.exists()
    assert __import__("json").loads(marker.read_text())["state"] == "candidate_retained"


def test_apply_keeps_recovered_candidate_when_outcome_marker_cannot_be_written(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationOutcome, MigrationPlan, SwitchController
    from cryptolabs_proxy.services import ServiceRegistry

    image = "proxy@sha256:reviewed"
    source = {
        "Id": "source-id",
        "Config": {"Image": "old"},
        "HostConfig": {"Binds": []},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["proxy"]}}},
    }

    class Engine:
        def inspect(self, container): return source

    plan = MigrationPlan.from_source("source-id", CUSTOM_PROXY_CONFIG, image)
    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=Engine())
    original_write = migrator._write_private

    def write_private(path, content):
        if path.name == "outcome.json":
            raise OSError("backup marker is unavailable")
        original_write(path, content)

    monkeypatch.setattr("cryptolabs_proxy.migration.os.geteuid", lambda: 0)
    monkeypatch.setattr(migrator, "plan", lambda *args: plan)
    monkeypatch.setattr(migrator, "_read_active_config", lambda *args: CUSTOM_PROXY_CONFIG)
    monkeypatch.setattr(migrator, "_validate_candidate", lambda *args: None)
    monkeypatch.setattr(migrator, "_write_private", write_private)
    monkeypatch.setattr(
        SwitchController,
        "apply",
        lambda *args, **kwargs: MigrationOutcome.candidate_retained("old proxy restoration was unhealthy"),
    )

    outcome = migrator.apply("cryptolabs-proxy", image, plan.migration_id, enable_vpm=True)

    assert outcome.state == "candidate_retained"
    assert "marker could not be written" in outcome.detail
    assert ServiceRegistry(tmp_path).get_service("vast-price-manager") is not None
    assert b"BEGIN CRYPTOLABS MANAGED VPM" in (tmp_path / "nginx.conf").read_bytes()


def test_manual_rollback_uses_readiness_deadline_for_preflight_restoration_and_recovery(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator, MigrationError

    migration_id = "deadline-migration"
    backup = tmp_path / "backups" / migration_id
    backup.mkdir(parents=True)
    source = {"Id": "old-id", "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["old"]}}}}
    (backup / "inspect.json").write_text(__import__("json").dumps(source))
    (backup / "registry-snapshot.json").write_text("{}")

    class Engine:
        def inspect(self, name):
            if name == "cryptolabs-proxy.rollback-deadline-migration":
                return source
            return {"Id": "candidate-id", "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["candidate"]}}}}
        def stop(self, *args, **kwargs): pass
        def disconnect(self, *args): pass
        def rename(self, *args): pass
        def connect(self, *args): pass
        def start(self, *args): pass
        def remove(self, *args, **kwargs): pass

    observed = []
    monkeypatch.setattr("cryptolabs_proxy.migration.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "cryptolabs_proxy.migration.wait_for_proxy_ready",
        lambda engine, container, probe, timeout: observed.append(("ready", timeout)) or True,
    )
    monkeypatch.setattr(
        "cryptolabs_proxy.migration.wait_for_container_healthy",
        lambda engine, container, timeout: observed.append(("healthy", timeout)) or False,
    )
    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=Engine(), timeout=7)

    with pytest.raises(MigrationError, match="healthy replacement was restored"):
        migrator.rollback("cryptolabs-proxy", migration_id)

    assert observed == [
        ("ready", migrator.readiness_timeout),
        ("healthy", migrator.readiness_timeout),
        ("ready", migrator.readiness_timeout),
    ]


def test_migration_helper_reports_retained_candidate_as_operator_action(monkeypatch, capsys):
    from cryptolabs_proxy.migration import MigrationOutcome

    spec = importlib.util.spec_from_file_location(
        "vpm_custom_config_migrate", REPOSITORY / "scripts" / "vpm-custom-config-migrate.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Migrator:
        def __init__(self, *args, **kwargs): pass
        def apply(self, *args, **kwargs):
            return MigrationOutcome.candidate_retained("source restoration was unhealthy")

    monkeypatch.setattr(module, "CustomConfigMigrator", Migrator)
    monkeypatch.setattr(
        "sys.argv",
        ["vpm-custom-config-migrate.py", "apply", "--proxy-image", "proxy@sha256:reviewed", "--migration-id", "repair"],
    )

    assert module.main() == 2
    assert __import__("json").loads(capsys.readouterr().out)["state"] == "candidate_retained"


def test_manual_rollback_blocks_lifecycle_command_until_runtime_and_registry_restore_finish(monkeypatch, tmp_path):
    from cryptolabs_proxy.migration import CustomConfigMigrator

    migration_id = "lock-migration"
    backup = tmp_path / "backups" / migration_id
    backup.mkdir(parents=True)
    source = {"Id": "old-id", "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["old"]}}}}
    (backup / "inspect.json").write_text(__import__("json").dumps(source))
    (backup / "registry-snapshot.json").write_text("{}")
    in_switch = threading.Event()
    release_switch = threading.Event()
    errors = []

    class Engine:
        def inspect(self, name):
            if name == "cryptolabs-proxy.rollback-lock-migration":
                return source
            return {"Id": "candidate-id", "NetworkSettings": {"Networks": {"cryptolabs": {"Aliases": ["candidate"]}}}}
        def stop(self, *args, **kwargs):
            in_switch.set()
            assert release_switch.wait(5)
        def disconnect(self, *args): pass
        def rename(self, *args): pass
        def connect(self, *args): pass
        def start(self, *args): pass
        def remove(self, *args, **kwargs): pass

    monkeypatch.setattr("cryptolabs_proxy.migration.os.geteuid", lambda: 0)
    monkeypatch.setattr("cryptolabs_proxy.migration.wait_for_proxy_ready", lambda *args: True)
    monkeypatch.setattr("cryptolabs_proxy.migration.wait_for_container_healthy", lambda *args: True)
    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=Engine())
    rollback_thread = threading.Thread(
        target=lambda: _rollback_in_thread(migrator, migration_id, errors),
        daemon=True,
    )
    rollback_thread.start()
    assert in_switch.wait(2)

    context = get_context("fork")
    entered = context.Event()
    results = context.Queue()
    process = context.Process(target=_register_service_after_rollback_lock, args=(str(tmp_path), entered, results))
    process.start()
    assert not entered.wait(0.4)

    release_switch.set()
    rollback_thread.join(5)
    process.join(5)
    assert not errors
    assert process.exitcode == 0
    assert entered.is_set()
    assert results.get(timeout=2)[0] == 0


def _rollback_in_thread(migrator, migration_id, errors):
    try:
        migrator.rollback("cryptolabs-proxy", migration_id)
    except Exception as error:  # pragma: no cover - asserted by caller
        errors.append(error)
