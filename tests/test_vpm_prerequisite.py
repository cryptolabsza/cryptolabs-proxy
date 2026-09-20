"""Tests for the fresh, sanitized Vast exporter prerequisite probe."""

from types import SimpleNamespace


def _result(returncode=0, stdout=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="sensitive diagnostic")


def test_prerequisite_requires_running_exporter_before_exec(monkeypatch):
    from cryptolabs_proxy import vpm_prerequisite

    monkeypatch.setattr(vpm_prerequisite.subprocess, "run", lambda *args, **kwargs: _result(stdout="false\n"))

    assert vpm_prerequisite.get_vpm_prerequisite() == {
        "configured": False,
        "reason": "exporter-not-running",
        "connected_account_count": 0,
    }


def test_prerequisite_returns_only_sanitized_connected_account_result(monkeypatch):
    from cryptolabs_proxy import vpm_prerequisite

    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[:2] == ["docker", "inspect"]:
            return _result(stdout="true\n")
        return _result(stdout='{"connected_account_count": 2}')

    monkeypatch.setattr(vpm_prerequisite.subprocess, "run", run)

    assert vpm_prerequisite.get_vpm_prerequisite() == {
        "configured": True,
        "reason": "ready",
        "connected_account_count": 2,
    }
    assert calls[1][:4] == ["docker", "exec", "vastai-exporter", "python3"]
    assert "MGMT_TOKEN" in calls[1][-1]
    assert "key_masked" not in calls[1][-1]


def test_exporter_probe_requires_the_provisioned_management_token():
    from cryptolabs_proxy import vpm_prerequisite

    assert "if not token:" in vpm_prerequisite._EXPORTER_PROBE
    assert 'headers={"X-Mgmt-Token": token}' in vpm_prerequisite._EXPORTER_PROBE
    assert "timeout=5" in vpm_prerequisite._EXPORTER_PROBE
    assert vpm_prerequisite.PROBE_TIMEOUT_SECONDS == 15


def test_prerequisite_fails_closed_for_empty_or_malformed_accounts_response(monkeypatch):
    from cryptolabs_proxy import vpm_prerequisite

    responses = iter([_result(stdout="true\n"), _result(stdout="not-json")])
    monkeypatch.setattr(vpm_prerequisite.subprocess, "run", lambda *args, **kwargs: next(responses))

    assert vpm_prerequisite.get_vpm_prerequisite() == {
        "configured": False,
        "reason": "unavailable",
        "connected_account_count": 0,
    }


def test_prerequisite_reports_no_connected_account_for_valid_empty_result(monkeypatch):
    from cryptolabs_proxy import vpm_prerequisite

    responses = iter([_result(stdout="true\n"), _result(stdout='{"connected_account_count": 0}')])
    monkeypatch.setattr(vpm_prerequisite.subprocess, "run", lambda *args, **kwargs: next(responses))

    assert vpm_prerequisite.get_vpm_prerequisite() == {
        "configured": False,
        "reason": "no-connected-account",
        "connected_account_count": 0,
    }
