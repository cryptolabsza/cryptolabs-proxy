"""Dry-run planning and bounded state helpers for custom VPM proxy migration.

This module intentionally does not contact Docker at import time. The calling
host helper owns Docker execution; these functions build deterministic plans
and create payloads without printing inspected configuration or environment.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any
from urllib.parse import quote

from .custom_config import configure_custom_config_mode, render_managed_vpm_config


class MigrationError(RuntimeError):
    """A custom-config migration precondition or compensated switch failed."""


@dataclass(frozen=True)
class MigrationOutcome:
    """The serving state reached by a completed compensating switch."""

    state: str
    detail: str = ""

    @classmethod
    def applied(cls) -> "MigrationOutcome":
        return cls("applied")

    @classmethod
    def candidate_retained(cls, detail: str) -> "MigrationOutcome":
        return cls("candidate_retained", detail)


# Keep this in sync with the image HEALTHCHECK in Dockerfile.  A candidate can
# remain in Docker's `starting` state until the start period and a scheduled
# health check have elapsed; the Engine request timeout is deliberately a
# separate, short transport bound.
DOCKER_HEALTH_START_PERIOD = 10
DOCKER_HEALTH_INTERVAL = 30
DOCKER_HEALTH_TIMEOUT = 10
DOCKER_HEALTH_RETRIES = 3
PROXY_READY_TIMEOUT = (
    DOCKER_HEALTH_START_PERIOD
    + DOCKER_HEALTH_INTERVAL * DOCKER_HEALTH_RETRIES
    + DOCKER_HEALTH_TIMEOUT
    + 10  # bounded local auth-probe allowance
)


@dataclass(frozen=True)
class MigrationPlan:
    container_id: str
    baseline_sha256: str
    image: str
    migration_id: str

    @classmethod
    def from_source(cls, container_id: str, baseline: bytes, image: str) -> "MigrationPlan":
        baseline_sha256 = hashlib.sha256(baseline).hexdigest()
        material = f"{container_id}:{baseline_sha256}:{image}".encode()
        return cls(container_id, baseline_sha256, image, hashlib.sha256(material).hexdigest()[:20])

    def sanitized_manifest(self) -> dict[str, str]:
        return {
            "migration_id": self.migration_id,
            "container_id": self.container_id,
            "baseline_sha256": self.baseline_sha256,
            "image": self.image,
        }


def _mount_request(mount: dict[str, Any]) -> dict[str, Any]:
    """Convert inspect mount data to the Docker create API representation."""
    mount_type = mount["Type"]
    if mount_type not in ("bind", "volume"):
        raise MigrationError(f"unsupported mount type {mount_type}; refusing to drop its options")
    source = mount.get("Name") if mount_type == "volume" else mount.get("Source")
    if not source:
        raise MigrationError(f"cannot preserve {mount_type} mount without a source")
    result = {
        "Type": mount_type,
        "Source": source,
        "Target": mount["Destination"],
        "ReadOnly": not mount.get("RW", True),
    }
    if mount_type == "bind" and mount.get("Propagation"):
        result["BindOptions"] = {"Propagation": mount["Propagation"]}
    return result


def endpoint_configurations(inspect: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return only user-configured endpoint fields accepted by Docker create."""
    source_networks = inspect.get("NetworkSettings", {}).get("Networks", {})
    # Inspect also reports Engine-assigned endpoint IDs, IP addresses, and
    # gateways. They are not valid create inputs; retain every user-configured
    # endpoint setting while allowing Docker to allocate those runtime fields.
    endpoint_fields = ("Aliases", "Links", "IPAMConfig", "MacAddress", "DriverOpts", "GwPriority")
    networks = {
        name: {field: deepcopy(endpoint[field]) for field in endpoint_fields if field in endpoint}
        for name, endpoint in source_networks.items()
    }
    if not networks:
        raise MigrationError("source proxy has no inspectable network endpoints")
    return networks


def build_recreate_request(inspect: dict[str, Any], image: str, candidate_config_path: str) -> dict[str, Any]:
    """Clone inspected Engine settings and add only the read-only config bind."""
    config = deepcopy(inspect["Config"])
    host_config = deepcopy(inspect["HostConfig"])
    config["Image"] = image
    mounts = [_mount_request(mount) for mount in inspect.get("Mounts", [])]
    if any(mount["Target"] == "/etc/nginx/nginx.conf" for mount in mounts):
        raise MigrationError("source proxy already has an nginx.conf mount")
    mounts.append({
        "Type": "bind",
        "Source": candidate_config_path,
        "Target": "/etc/nginx/nginx.conf",
        "ReadOnly": True,
    })
    # Docker accepts Mounts as the declarative form. Removing Binds prevents a
    # duplicate mount while every source mount is reconstructed above.
    host_config.pop("Binds", None)
    host_config["Mounts"] = mounts
    networks = endpoint_configurations(inspect)
    return {
        "Config": config,
        "HostConfig": host_config,
        "NetworkingConfig": {"EndpointsConfig": networks},
    }


def prepare_custom_registry(registry, baseline_path: Path, enable_vpm: bool) -> bytes:
    """Configure custom mode and return the candidate config without reloading."""
    configure_custom_config_mode(registry.config, baseline_path)
    if enable_vpm:
        from .services import DEFAULT_SERVICES
        registry.services["vast-price-manager"] = deepcopy(DEFAULT_SERVICES["vast-price-manager"])
    else:
        registry.services.pop("vast-price-manager", None)
    return render_managed_vpm_config(baseline_path.read_bytes(), enable_vpm)


class SwitchController:
    """Compensating swap sequence with an injected Engine adapter for testing."""

    def __init__(self, engine, health_check, rollback_health_check=None):
        self.engine = engine
        self.health_check = health_check
        self.rollback_health_check = rollback_health_check or health_check

    def apply(
        self,
        source_id: str,
        migration_id: str,
        request: dict[str, Any],
        candidate_name: str | None = None,
    ) -> MigrationOutcome:
        candidate_name = candidate_name or source_id
        rollback_name = f"{candidate_name}.rollback-{migration_id}"
        held_candidate_name = f"{candidate_name}.candidate-{migration_id}"
        endpoints = request["NetworkingConfig"]["EndpointsConfig"]
        candidate_created = False
        renamed = False
        stopped = False
        detached_source_networks: list[str] = []
        try:
            self.engine.stop(source_id)
            stopped = True
            for network in endpoints:
                self.engine.disconnect(source_id, network)
                detached_source_networks.append(network)
            self.engine.rename(source_id, rollback_name)
            renamed = True
            self.engine.create(candidate_name, request)
            candidate_created = True
            self.engine.start(candidate_name)
            if not self.health_check(candidate_name):
                raise MigrationError("candidate proxy health check failed")
        except Exception as error:
            try:
                if candidate_created:
                    self.engine.stop(candidate_name, ignore_missing=True)
                    for network in endpoints:
                        self.engine.disconnect(candidate_name, network)
                    self.engine.rename(candidate_name, held_candidate_name)
                if renamed:
                    self.engine.rename(rollback_name, candidate_name)
                    for network, endpoint in endpoints.items():
                        self.engine.connect(candidate_name, network, endpoint)
                    self.engine.start(candidate_name)
                    if not self.rollback_health_check(candidate_name):
                        if candidate_created:
                            self.engine.stop(candidate_name, ignore_missing=True)
                            for network in endpoints:
                                self.engine.disconnect(candidate_name, network)
                            self.engine.rename(candidate_name, rollback_name)
                            self.engine.rename(held_candidate_name, candidate_name)
                            for network, endpoint in endpoints.items():
                                self.engine.connect(candidate_name, network, endpoint)
                            self.engine.start(candidate_name)
                            if not self.health_check(candidate_name):
                                raise MigrationError("candidate and restored proxy health checks both failed")
                            return MigrationOutcome.candidate_retained(
                                "source restoration health check failed; recovered candidate is serving"
                            )
                        raise MigrationError("restored proxy health check failed")
                    if candidate_created:
                        self.engine.remove(held_candidate_name, ignore_missing=True)
                elif stopped:
                    # A failed disconnect or rename leaves the source under
                    # its original name but stopped. Restore only endpoints
                    # whose detach request completed, preserving static IPs
                    # and aliases before restarting it.
                    for network in detached_source_networks:
                        self.engine.connect(source_id, network, endpoints[network])
                    self.engine.start(source_id)
            except Exception as rollback_error:
                raise MigrationError(
                    f"custom proxy migration failed: {error}; rollback also failed: {rollback_error}"
                ) from rollback_error
            if isinstance(error, MigrationError):
                raise
            raise MigrationError(f"custom proxy migration failed: {error}") from error
        return MigrationOutcome.applied()


def wait_for_proxy_ready(engine, container: str, auth_probe, timeout: int, interval: float = 0.25) -> bool:
    """Wait through Docker health startup and require anonymous auth rejection."""
    deadline = time.monotonic() + timeout
    while True:
        state = engine.inspect(container).get("State", {})
        health = state.get("Health", {}).get("Status")
        if not state.get("Running") or health == "unhealthy":
            return False
        if health == "healthy":
            try:
                return bool(auth_probe())
            except OSError:
                return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def wait_for_container_healthy(engine, container: str, timeout: int, interval: float = 0.25) -> bool:
    """Bounded health wait used when restoring the pre-VPM proxy image."""
    deadline = time.monotonic() + timeout
    while True:
        state = engine.inspect(container).get("State", {})
        health = state.get("Health", {}).get("Status")
        if not state.get("Running") or health == "unhealthy":
            return False
        if health == "healthy":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


class _UnixHTTPConnection(http.client.HTTPConnection):
    """Small standard-library Docker Engine API client over its Unix socket."""

    def __init__(self, socket_path: str, timeout: int = 15):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class DockerEngine:
    """Bounded Engine actions that keep inspect/config values out of stdout."""

    def __init__(self, socket_path: str = "/var/run/docker.sock", timeout: int = 15):
        self.socket_path = socket_path
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict | None = None, allowed=(200, 201, 204)):
        connection = _UnixHTTPConnection(self.socket_path, self.timeout)
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read()
        except OSError as error:
            raise MigrationError(f"Docker Engine request failed: {error}") from error
        finally:
            connection.close()
        if response.status not in allowed:
            # Engine failures can include sensitive Config data; retain only
            # the status, never echo its body into command output.
            raise MigrationError(f"Docker Engine {method} {path} returned HTTP {response.status}")
        return content

    def inspect(self, container: str) -> dict[str, Any]:
        return json.loads(self._request("GET", f"/containers/{quote(container, safe='')}/json"))

    def stop(self, container: str, ignore_missing: bool = False):
        allowed = (204, 304, 404) if ignore_missing else (204, 304)
        # Leave the Unix-socket read timeout enough headroom to receive the
        # Engine response after its graceful-stop period.
        grace = max(1, self.timeout - 2)
        self._request("POST", f"/containers/{quote(container, safe='')}/stop?t={grace}", allowed=allowed)

    def rename(self, old: str, new: str):
        self._request("POST", f"/containers/{quote(old, safe='')}/rename?name={quote(new, safe='')}", allowed=(204,))

    def create(self, name: str, request: dict[str, Any]):
        payload = deepcopy(request["Config"])
        payload["HostConfig"] = request["HostConfig"]
        payload["NetworkingConfig"] = request["NetworkingConfig"]
        self._request("POST", f"/containers/create?name={quote(name, safe='')}", payload, allowed=(201,))

    def start(self, container: str):
        self._request("POST", f"/containers/{quote(container, safe='')}/start", allowed=(204, 304))

    def remove(self, container: str, ignore_missing: bool = False):
        allowed = (204, 404) if ignore_missing else (204,)
        self._request("DELETE", f"/containers/{quote(container, safe='')}?force=1", allowed=allowed)

    def disconnect(self, container: str, network: str):
        self._request(
            "POST",
            f"/networks/{quote(network, safe='')}/disconnect",
            {"Container": container, "Force": True},
            allowed=(200,),
        )

    def connect(self, container: str, network: str, endpoint: dict[str, Any]):
        self._request(
            "POST",
            f"/networks/{quote(network, safe='')}/connect",
            {"Container": container, "EndpointConfig": endpoint},
            allowed=(200,),
        )

    def healthy(self, container: str) -> bool:
        state = self.inspect(container).get("State", {})
        health = state.get("Health", {}).get("Status")
        return state.get("Running") and health in (None, "healthy")


class CustomConfigMigrator:
    """Explicit plan/apply/rollback workflow for one custom proxy container."""

    def __init__(
        self,
        config_dir: Path,
        backup_root: Path,
        engine: DockerEngine | None = None,
        timeout: int = 15,
        readiness_timeout: int = PROXY_READY_TIMEOUT,
    ):
        self.config_dir = config_dir
        self.backup_root = backup_root
        self.engine = engine or DockerEngine(timeout=timeout)
        # `timeout` bounds each Unix socket/subprocess/HTTP operation.  It is
        # not the lifecycle deadline, because Docker's own health cadence is
        # intentionally much longer.
        self.timeout = timeout
        if readiness_timeout < PROXY_READY_TIMEOUT:
            raise MigrationError(
                f"readiness timeout must be at least {PROXY_READY_TIMEOUT} seconds for the proxy healthcheck"
            )
        self.readiness_timeout = readiness_timeout

    def _read_active_config(self, container: str) -> bytes:
        try:
            result = subprocess.run(
                ["docker", "exec", container, "cat", "/etc/nginx/nginx.conf"],
                capture_output=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise MigrationError(f"cannot read active proxy config: {error}") from error
        if result.returncode:
            raise MigrationError("cannot read active proxy config")
        return result.stdout

    def plan(self, container: str, image: str) -> MigrationPlan:
        """Read only: return a deterministic, sanitized migration identity."""
        if "@sha256:" not in image:
            raise MigrationError("proxy image must be an immutable sha256 digest")
        inspect = self.engine.inspect(container)
        return MigrationPlan.from_source(inspect["Id"], self._read_active_config(container), image)

    def _backup_path(self, migration_id: str) -> Path:
        return self.backup_root / migration_id

    @staticmethod
    def _write_private(path: Path, content: bytes):
        path.write_bytes(content)
        path.chmod(0o600)

    def _validate_candidate(self, image: str, candidate: Path, inspect: dict[str, Any], migration_id: str):
        ssl_mount = next((m for m in inspect.get("Mounts", []) if m.get("Destination") == "/etc/nginx/ssl"), None)
        if not ssl_mount:
            raise MigrationError("source proxy has no /etc/nginx/ssl mount for candidate validation")
        validation_name = f"cryptolabs-vpm-validate-{migration_id}"[:63]
        command = [
            "docker", "run", "--name", validation_name,
            "--label", f"cryptolabs.migration.validation={migration_id}",
            "--network", "none", "--entrypoint", "nginx",
            "-v", f"{candidate}:/etc/nginx/nginx.conf:ro",
            "-v", f"{ssl_mount['Source']}:/etc/nginx/ssl:ro",
            image, "-t",
        ]
        try:
            result = subprocess.run(command, capture_output=True, timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise MigrationError(f"candidate Nginx validation could not run: {error}") from error
        finally:
            # The image entrypoint may ignore argv or outlive a killed Docker
            # client. Explicitly remove only our unique labeled container.
            subprocess.run(
                ["docker", "rm", "-f", validation_name],
                capture_output=True,
                timeout=self.timeout,
            )
        if result.returncode:
            raise MigrationError("candidate Nginx validation failed")

    def _anonymous_auth_is_rejected(self) -> bool:
        """The replacement must expose the new endpoint without a session."""
        connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=self.timeout)
        try:
            connection.request("GET", "/auth/vast-price-manager/authorize")
            return connection.getresponse().status == 401
        except OSError:
            return False
        finally:
            connection.close()

    def apply(self, container: str, image: str, migration_id: str, enable_vpm: bool) -> MigrationOutcome:
        """Snapshot privately, validate, then perform a compensating proxy-only swap."""
        if os.geteuid() != 0:
            raise MigrationError("custom proxy migration must run as root")
        from .cli import registry_lock
        with registry_lock(self.config_dir):
            # Rebuild the read-only plan while holding the same lock that
            # serializes later VPM register/unregister writes.
            plan = self.plan(container, image)
            if plan.migration_id != migration_id:
                raise MigrationError("migration ID does not match the current source container/config/image")
            backup = self._backup_path(migration_id)
            if backup.exists():
                raise MigrationError("migration backup already exists")
            self.backup_root.mkdir(parents=True, mode=0o700)
            self.backup_root.chmod(0o700)
            backup.mkdir(parents=True, mode=0o700)
            backup.chmod(0o700)
            inspect = self.engine.inspect(container)
            baseline = self._read_active_config(container)
            current = MigrationPlan.from_source(inspect["Id"], baseline, image)
            if current != plan:
                raise MigrationError("source container ID or config changed before switch")
            self._write_private(backup / "baseline.nginx.conf", baseline)
            self._write_private(backup / "inspect.json", json.dumps(inspect, sort_keys=True).encode())
            from .services import ServiceRegistry
            registry = ServiceRegistry(self.config_dir)
            previous = _snapshot_registry_files(registry)
            _write_registry_backup(backup, previous)
            candidate = self.config_dir / "nginx.conf"
            previous_candidate = candidate.read_bytes() if candidate.exists() else None
            try:
                candidate_content = prepare_custom_registry(registry, backup / "baseline.nginx.conf", enable_vpm)
                self._write_private(candidate, candidate_content)
                registry.save()
                self._validate_candidate(image, candidate, inspect, migration_id)
                request = build_recreate_request(inspect, image, str(candidate))
                outcome = SwitchController(
                    self.engine,
                    lambda name: wait_for_proxy_ready(
                        self.engine,
                        name,
                        self._anonymous_auth_is_rejected,
                        self.readiness_timeout,
                    ),
                    rollback_health_check=lambda name: wait_for_container_healthy(
                        self.engine,
                        name,
                        self.readiness_timeout,
                    ),
                ).apply(plan.container_id, migration_id, request, candidate_name=container)
            except Exception:
                _restore_registry_files(previous)
                if previous_candidate is None:
                    candidate.unlink(missing_ok=True)
                else:
                    self._write_private(candidate, previous_candidate)
                raise
            # A retained candidate is the live recovery path. Marker writing
            # is diagnostic only and must never re-enter generic cleanup that
            # would unlink/revert the configuration it is serving.
            if outcome.state == "candidate_retained":
                try:
                    self._write_private(
                        backup / "outcome.json",
                        json.dumps({"state": outcome.state, "detail": outcome.detail}, sort_keys=True).encode(),
                    )
                except OSError:
                    return MigrationOutcome.candidate_retained(
                        f"{outcome.detail}; recovery marker could not be written"
                    )
            return outcome

    def rollback(self, container: str, migration_id: str) -> MigrationOutcome:
        """Restore only this proxy without discarding its healthy replacement."""
        if os.geteuid() != 0:
            raise MigrationError("custom proxy rollback must run as root")
        from .cli import registry_lock
        # Match lifecycle register/unregister: the same lock covers runtime
        # changes and the registry/config restore so no command observes or
        # persists a split state.
        with registry_lock(self.config_dir):
            return self._rollback_locked(container, migration_id)

    def _rollback_locked(self, container: str, migration_id: str) -> MigrationOutcome:
        backup = self._backup_path(migration_id)
        if not backup.is_dir():
            raise MigrationError("migration backup does not exist")
        rollback_name = f"{container}.rollback-{migration_id}"
        held_candidate = f"{container}.candidate-{migration_id}"
        source = json.loads((backup / "inspect.json").read_text())
        restored = self.engine.inspect(rollback_name)
        if restored.get("Id") != source.get("Id"):
            raise MigrationError("rollback source does not match the private backup")
        # Prove the replacement works before it is stopped or renamed.
        if not wait_for_proxy_ready(self.engine, container, self._anonymous_auth_is_rejected, self.readiness_timeout):
            raise MigrationError("current replacement is not healthy; refusing to remove its recovery path")
        source_endpoints = endpoint_configurations(source)
        candidate_endpoints = endpoint_configurations(self.engine.inspect(container))
        candidate_held = False
        source_promoted = False
        detached_candidate_networks: list[str] = []
        try:
            self.engine.stop(container)
            for network in candidate_endpoints:
                self.engine.disconnect(container, network)
                detached_candidate_networks.append(network)
            self.engine.rename(container, held_candidate)
            candidate_held = True
            self.engine.rename(rollback_name, container)
            source_promoted = True
            for network, endpoint in source_endpoints.items():
                self.engine.connect(container, network, endpoint)
            self.engine.start(container)
            if not wait_for_container_healthy(self.engine, container, self.readiness_timeout):
                raise MigrationError("restored proxy health check failed")
        except Exception as error:
            try:
                if source_promoted:
                    self.engine.stop(container, ignore_missing=True)
                    for network in source_endpoints:
                        self.engine.disconnect(container, network)
                    self.engine.rename(container, rollback_name)
                if candidate_held:
                    self.engine.rename(held_candidate, container)
                    for network, endpoint in candidate_endpoints.items():
                        self.engine.connect(container, network, endpoint)
                    self.engine.start(container)
                    if not wait_for_proxy_ready(
                        self.engine,
                        container,
                        self._anonymous_auth_is_rejected,
                        self.readiness_timeout,
                    ):
                        raise MigrationError("candidate recovery health check failed")
                else:
                    # Candidate was never renamed, so restore exactly the
                    # networks detached before the failed rename/disconnect.
                    for network in detached_candidate_networks:
                        self.engine.connect(container, network, candidate_endpoints[network])
                    self.engine.start(container)
            except Exception as recovery_error:
                raise MigrationError(
                    f"rollback failed: {error}; candidate recovery also failed: {recovery_error}"
                ) from recovery_error
            raise MigrationError("rollback failed; healthy replacement was restored") from error
        self.engine.remove(held_candidate, ignore_missing=True)
        _restore_registry_files(_read_registry_backup(backup))
        return MigrationOutcome("rolled_back")


def _snapshot_registry_files(registry) -> dict[Path, bytes | None]:
    paths = [registry.services_file, registry.config_file, registry.config_dir / "nginx.conf"]
    return {path: path.read_bytes() if path.exists() else None for path in paths}


def _write_registry_backup(backup: Path, snapshot: dict[Path, bytes | None]):
    encoded = {str(path): content.decode("latin1") if content is not None else None for path, content in snapshot.items()}
    CustomConfigMigrator._write_private(backup / "registry-snapshot.json", json.dumps(encoded).encode())


def _read_registry_backup(backup: Path) -> dict[Path, bytes | None]:
    encoded = json.loads((backup / "registry-snapshot.json").read_text())
    return {Path(path): content.encode("latin1") if content is not None else None for path, content in encoded.items()}


def _restore_registry_files(snapshot: dict[Path, bytes | None]):
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
