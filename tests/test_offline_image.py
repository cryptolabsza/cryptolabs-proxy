"""Offline immutable local image-ID coverage for custom proxy migration."""

from pathlib import Path

import pytest

from cryptolabs_proxy.migration import (
    CustomConfigMigrator,
    MigrationError,
    build_recreate_request,
)


LOCAL_ID = "sha256:" + "b" * 64


def test_migration_plan_accepts_full_canonical_local_image_id(monkeypatch, tmp_path: Path):
    class Engine:
        def inspect(self, _container):
            return {"Id": "source-id"}

    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=Engine())
    monkeypatch.setattr(migrator, "_read_active_config", lambda _container: b"baseline")

    assert migrator.plan("cryptolabs-proxy", LOCAL_ID).image == LOCAL_ID


@pytest.mark.parametrize("image", ["sha256:" + "a" * 63, "sha256:" + "A" * 64])
def test_migration_plan_rejects_truncated_or_noncanonical_local_image_ids(image, tmp_path: Path):
    migrator = CustomConfigMigrator(tmp_path, tmp_path / "backups", engine=object())

    with pytest.raises(MigrationError, match="immutable"):
        migrator.plan("cryptolabs-proxy", image)


def test_candidate_validation_and_create_request_keep_exact_local_image_id(monkeypatch, tmp_path: Path):
    commands = []

    class Result:
        returncode = 0

    def run(command, **_kwargs):
        commands.append(command)
        if command[:4] == ["docker", "image", "inspect", "--format"]:
            return type("InspectResult", (), {"returncode": 0, "stdout": f"{LOCAL_ID}\n", "stderr": ""})()
        return Result()

    monkeypatch.setattr("cryptolabs_proxy.migration.subprocess.run", run)
    candidate = tmp_path / "nginx.conf"
    candidate.write_text("events {}")
    inspect = {"Mounts": [{"Destination": "/etc/nginx/ssl", "Source": "/ssl"}]}

    CustomConfigMigrator(tmp_path, tmp_path / "backups")._validate_candidate(
        LOCAL_ID, candidate, inspect, "offline-id"
    )
    request = build_recreate_request(
        {"Config": {}, "HostConfig": {}, "Mounts": [], "NetworkSettings": {"Networks": {"cryptolabs": {}}}},
        LOCAL_ID,
        str(candidate),
    )

    assert commands[0] == ["docker", "image", "inspect", "--format", "{{.Id}}", LOCAL_ID]
    assert LOCAL_ID in commands[1]
    assert request["Config"]["Image"] == LOCAL_ID


@pytest.mark.parametrize(
    "inspect_result",
    [
        (1, "", "No such image"),
        (0, "sha256:" + "c" * 64 + "\n", ""),
    ],
)
def test_local_image_id_missing_or_mismatched_rejects_before_candidate_validator_runs(monkeypatch, tmp_path: Path, inspect_result):
    commands = []
    returncode, stdout, stderr = inspect_result

    class Result:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def run(command, **_kwargs):
        commands.append(command)
        return Result(returncode, stdout, stderr)

    monkeypatch.setattr("cryptolabs_proxy.migration.subprocess.run", run)
    candidate = tmp_path / "nginx.conf"
    candidate.write_text("events {}")
    inspect = {"Mounts": [{"Destination": "/etc/nginx/ssl", "Source": "/ssl"}]}

    with pytest.raises(MigrationError, match="offline image missing"):
        CustomConfigMigrator(tmp_path, tmp_path / "backups")._validate_candidate(
            LOCAL_ID, candidate, inspect, "offline-id"
        )

    assert commands == [["docker", "image", "inspect", "--format", "{{.Id}}", LOCAL_ID]]
