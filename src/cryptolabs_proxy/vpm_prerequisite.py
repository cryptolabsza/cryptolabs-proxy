"""Fresh, secret-safe readiness check for enabling Vast Price Manager."""

import json
import subprocess


EXPORTER_CONTAINER = "vastai-exporter"
PROBE_TIMEOUT_SECONDS = 15

# The command intentionally executes inside the exporter. That is the only
# place the management token is read; stdout is limited to a connected count.
_EXPORTER_PROBE = r"""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

token = os.environ.get("MGMT_TOKEN")
if not token:
    raise SystemExit(1)
request = Request(
    "http://127.0.0.1:8622/api/accounts",
    headers={"X-Mgmt-Token": token},
)
try:
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    # Ignore inherited HTTP(S)_PROXY values and reject redirects: the token is
    # valid only for the exporter's loopback management API.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=5) as response:
        if response.status != 200:
            raise SystemExit(1)
        payload = json.load(response)
except (HTTPError, URLError, OSError, ValueError):
    raise SystemExit(1)

accounts = payload.get("accounts") if isinstance(payload, dict) else None
if not isinstance(accounts, list):
    raise SystemExit(1)
count = sum(
    1 for account in accounts
    if isinstance(account, dict) and account.get("status") == "connected"
)
print(json.dumps({"connected_account_count": count}))
"""


def _result(configured: bool, reason: str, count: int = 0) -> dict:
    """Return the sole public prerequisite representation."""
    return {
        "configured": configured,
        "reason": reason,
        "connected_account_count": count,
    }


def get_vpm_prerequisite() -> dict:
    """Check exporter availability and connected accounts without exposing secrets.

    This function is deliberately uncached. Lifecycle callers use its current
    result immediately before their first VPM registration or custom enable.
    """
    try:
        running = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", EXPORTER_CONTAINER],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return _result(False, "exporter-not-running")

    if running.returncode != 0 or running.stdout.strip().lower() != "true":
        return _result(False, "exporter-not-running")

    try:
        probe = subprocess.run(
            ["docker", "exec", EXPORTER_CONTAINER, "python3", "-c", _EXPORTER_PROBE],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return _result(False, "unavailable")

    if probe.returncode != 0:
        return _result(False, "unavailable")
    try:
        payload = json.loads(probe.stdout)
        count = payload["connected_account_count"]
    except (TypeError, ValueError, KeyError):
        return _result(False, "unavailable")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return _result(False, "unavailable")
    if count == 0:
        return _result(False, "no-connected-account")
    return _result(True, "ready", count)
