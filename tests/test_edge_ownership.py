"""CryptoLabs' own public wk01 sites are served by the common proxy in
cryptolabs-ai-platform (services/nginx-configs), not by this customer fleet
proxy product. These tests keep wk01 routing out of the shipped nginx config
and templates."""

import re
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
WK01_ADDRESS = "192.168.1.101"
SERVER_NAME = re.compile(r"^\s*server_name\s+([^;]*);", re.MULTILINE)


def _nginx_files():
    files = [REPOSITORY / "nginx" / "nginx.conf"]
    files += sorted((REPOSITORY / "src" / "cryptolabs_proxy" / "templates").glob("*.j2"))
    return files


def _server_names(text):
    names = []
    for match in SERVER_NAME.finditer(text):
        names.extend(match.group(1).split())
    return names


def _rendered_templates(tmp_path):
    from cryptolabs_proxy.config import generate_nginx_config
    from cryptolabs_proxy.services import DEFAULT_SERVICES

    generate_nginx_config(tmp_path, "fleet.example.test", services=dict(DEFAULT_SERVICES))
    plain = (tmp_path / "nginx.conf").read_text()
    generate_nginx_config(tmp_path, "fleet.example.test", letsencrypt=True, services=dict(DEFAULT_SERVICES))
    return [plain, (tmp_path / "nginx.conf").read_text()]


def test_scanned_files_exist():
    names = [path.name for path in _nginx_files()]
    assert "nginx.conf" in names and "nginx.conf.j2" in names


@pytest.mark.parametrize("path", _nginx_files(), ids=lambda path: path.name)
def test_shipped_nginx_files_do_not_route_to_wk01(path):
    assert WK01_ADDRESS not in path.read_text()


@pytest.mark.parametrize("path", _nginx_files(), ids=lambda path: path.name)
def test_shipped_nginx_files_do_not_serve_cryptolabs_co_za_hosts(path):
    offenders = [n for n in _server_names(path.read_text()) if n.rstrip(".").endswith(".cryptolabs.co.za")]
    assert offenders == []


def test_rendered_template_does_not_route_to_wk01_or_serve_cryptolabs_co_za(tmp_path):
    for config in _rendered_templates(tmp_path):
        assert "server {" in config
        assert WK01_ADDRESS not in config
        offenders = [n for n in _server_names(config) if n.rstrip(".").endswith(".cryptolabs.co.za")]
        assert offenders == []


def test_nginx_conf_points_to_the_common_proxy():
    text = (REPOSITORY / "nginx" / "nginx.conf").read_text()
    assert "cryptolabs-ai-platform" in text
    assert "services/nginx-configs" in text


def test_readme_points_to_the_common_proxy():
    text = (REPOSITORY / "README.md").read_text()
    assert "cryptolabs-ai-platform" in text
    assert "services/nginx-configs" in text
