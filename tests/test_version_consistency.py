"""The package version must be the same in pyproject.toml and __init__.py."""
import re
from pathlib import Path

import cryptolabs_proxy

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_and_dunder_version_match():
    text = (ROOT / "pyproject.toml").read_text()
    pyproject = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE).group(1)
    assert pyproject == cryptolabs_proxy.__version__
