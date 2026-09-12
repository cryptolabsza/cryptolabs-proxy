"""VPM-only management for a preserved, custom Nginx baseline."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .config import render_vpm_fragment


CUSTOM_CONFIG_KEY = "custom_config"
CUSTOM_CONFIG_MODE = "vpm-managed"
MANAGED_BEGIN = b"# BEGIN CRYPTOLABS MANAGED VPM"
MANAGED_END = b"# END CRYPTOLABS MANAGED VPM"
_ANCHOR = re.compile(rb"^[ \t]*location[ \t]+@login_redirect[ \t]*\{")


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


def render_managed_vpm_config(baseline: bytes, enabled: bool) -> bytes:
    """Return baseline bytes unchanged or splice the reviewed fragment after its anchor."""
    if not enabled:
        return baseline
    if MANAGED_BEGIN in baseline or MANAGED_END in baseline:
        raise CustomConfigError("custom-config baseline already contains a managed VPM delimiter")
    if b"upstream auth_server" not in baseline or b"location @service_unavailable" not in baseline:
        raise CustomConfigError("custom-config baseline lacks required Fleet auth or service-unavailable handlers")
    offset = _anchor_end_offset(baseline)
    fragment = render_vpm_fragment().encode()
    block = MANAGED_BEGIN + b"\n" + fragment.rstrip() + b"\n" + MANAGED_END + b"\n"
    return baseline[:offset] + block + baseline[offset:]


def ensure_vpm_only_change(previous: dict, requested: dict) -> None:
    """Custom mode never rewrites routes for a service other than VPM."""
    changed = {
        name
        for name in set(previous) | set(requested)
        if previous.get(name) != requested.get(name)
    }
    if changed - {"vast-price-manager"}:
        raise CustomConfigError("custom-config mode permits only vast-price-manager lifecycle mutations")
