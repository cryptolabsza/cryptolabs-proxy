"""VPM-only management for a preserved, custom Nginx baseline."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .config import render_vpm_fragment, render_vpm_internal_auth_blocks


CUSTOM_CONFIG_KEY = "custom_config"
CUSTOM_CONFIG_MODE = "vpm-managed"
MANAGED_BEGIN = b"# BEGIN CRYPTOLABS MANAGED VPM"
MANAGED_END = b"# END CRYPTOLABS MANAGED VPM"
AUTH_DENIES_BEGIN = b"# BEGIN CRYPTOLABS MANAGED INTERNAL AUTH DENIES"
AUTH_DENIES_END = b"# END CRYPTOLABS MANAGED INTERNAL AUTH DENIES"
_ANCHOR = re.compile(rb"^[ \t]*location[ \t]+@login_redirect[ \t]*\{")
_HTTP = re.compile(rb"^[ \t]*http[ \t]*\{")
_SERVER = re.compile(rb"^[ \t]*server[ \t]*\{")


class CustomConfigError(RuntimeError):
    """The preserved baseline cannot safely receive a VPM-only mutation."""


def configure_custom_config_mode(config: dict, baseline_path: Path) -> None:
    """Store the immutable baseline identity in existing registry settings."""
    baseline = baseline_path.read_bytes()
    config[CUSTOM_CONFIG_KEY] = {
        "mode": CUSTOM_CONFIG_MODE,
        "baseline_path": str(baseline_path),
        "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
    }


def custom_config_settings(config: dict) -> dict | None:
    settings = config.get(CUSTOM_CONFIG_KEY)
    if settings and settings.get("mode") == CUSTOM_CONFIG_MODE:
        return settings
    return None


def load_verified_baseline(config: dict) -> bytes:
    """Read the root-owned baseline only when its configured hash still matches."""
    settings = custom_config_settings(config)
    if not settings:
        raise CustomConfigError("custom-config mode is not configured")
    path = Path(settings["baseline_path"])
    baseline = path.read_bytes()
    actual = hashlib.sha256(baseline).hexdigest()
    if actual != settings.get("baseline_sha256"):
        raise CustomConfigError("custom-config baseline SHA-256 changed; refusing mutation")
    return baseline


def _strip_comments_and_strings(line: bytes) -> bytes:
    """Keep braces structural while ignoring simple quoted Nginx directive text."""
    result = bytearray()
    quote = None
    escaped = False
    for char in line:
        if quote:
            if escaped:
                escaped = False
            elif char == ord("\\"):
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in (ord("'"), ord('"')):
            quote = char
        elif char == ord("#"):
            break
        else:
            result.append(char)
    return bytes(result)


def _structural_brace_events(line: bytes) -> list[tuple[int, int]]:
    """Return brace positions that are outside quoted strings and comments."""
    events = []
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif char == ord("\\"):
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in (ord("'"), ord('"')):
            quote = char
        elif char == ord("#"):
            break
        elif char in (ord("{"), ord("}")):
            events.append((index, char))
    return events


def _anchor_end_offset(baseline: bytes) -> int:
    lines = baseline.splitlines(keepends=True)
    anchors = [index for index, line in enumerate(lines) if _ANCHOR.match(line)]
    if len(anchors) != 1:
        raise CustomConfigError("custom-config baseline must contain exactly one location @login_redirect anchor")

    anchor = anchors[0]
    depth = 0
    for line in lines[:anchor]:
        structural = _strip_comments_and_strings(line)
        depth += structural.count(b"{") - structural.count(b"}")
    target_depth = depth
    offset = sum(len(line) for line in lines[:anchor])
    for line in lines[anchor:]:
        structural = _strip_comments_and_strings(line)
        depth += structural.count(b"{") - structural.count(b"}")
        offset += len(line)
        if depth == target_depth:
            return offset
    raise CustomConfigError("custom-config login redirect anchor has unbalanced Nginx braces")


def _http_server_end_offsets(baseline: bytes) -> list[int]:
    """Locate every HTTP server closing brace without parsing quoted braces."""
    depth = 0
    http_depth = None
    server_parents = []
    offsets = []
    offset = 0

    for line in baseline.splitlines(keepends=True):
        events = _structural_brace_events(line)
        http_open = None
        server_open = None
        if http_depth is None and _HTTP.match(line):
            http_open = next((index for index, char in events if char == ord("{")), None)
        elif http_depth is not None and depth == http_depth + 1 and _SERVER.match(line):
            server_open = next((index for index, char in events if char == ord("{")), None)

        for index, char in events:
            if char == ord("{"):
                if index == http_open:
                    http_depth = depth
                if index == server_open:
                    server_parents.append(depth)
                depth += 1
            else:
                depth -= 1
                if server_parents and depth == server_parents[-1]:
                    server_parents.pop()
                    offsets.append(offset + index)
                if http_depth is not None and depth == http_depth:
                    http_depth = None
        offset += len(line)

    if http_depth is not None or server_parents:
        raise CustomConfigError("custom-config HTTP server blocks have unbalanced Nginx braces")
    if not offsets:
        raise CustomConfigError("custom-config baseline must contain at least one HTTP server block")
    return offsets


def render_managed_vpm_config(baseline: bytes, enabled: bool) -> bytes:
    """Splice auth denies and, when enabled, the VPM route after the anchor.

    The auth server is always installed, so its VPM-only authority endpoints
    must remain private even after VPM itself is unregistered.  The source
    baseline is never changed: each render starts from its recorded bytes,
    which keeps a migration rollback byte-exact.
    """
    if any(marker in baseline for marker in (
        MANAGED_BEGIN, MANAGED_END, AUTH_DENIES_BEGIN, AUTH_DENIES_END,
    )):
        raise CustomConfigError("custom-config baseline already contains a managed VPM delimiter")
    if b"upstream auth_server" not in baseline or b"location @service_unavailable" not in baseline:
        raise CustomConfigError("custom-config baseline lacks required Fleet auth or service-unavailable handlers")
    anchor_offset = _anchor_end_offset(baseline)
    server_end_offsets = _http_server_end_offsets(baseline)
    auth_denies = render_vpm_internal_auth_blocks().encode().rstrip()
    auth_block = b"\n" + AUTH_DENIES_BEGIN + b"\n" + auth_denies + b"\n" + AUTH_DENIES_END + b"\n"
    insertions = [(offset, auth_block) for offset in server_end_offsets]
    if enabled:
        fragment = render_vpm_fragment().encode().rstrip()
        vpm_block = MANAGED_BEGIN + b"\n" + fragment + b"\n" + MANAGED_END + b"\n"
        insertions.append((anchor_offset, vpm_block))

    rendered = baseline
    for offset, block in sorted(insertions, reverse=True):
        rendered = rendered[:offset] + block + rendered[offset:]
    return rendered


def ensure_vpm_only_change(previous: dict, requested: dict) -> None:
    """Custom mode never rewrites routes for a service other than VPM."""
    changed = {
        name
        for name in set(previous) | set(requested)
        if previous.get(name) != requested.get(name)
    }
    if changed - {"vast-price-manager"}:
        raise CustomConfigError("custom-config mode permits only vast-price-manager lifecycle mutations")
