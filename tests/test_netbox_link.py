"""Site-specific NetBox links use Fleet settings, never NetBox credentials."""

import json
from pathlib import Path

import pytest

from cryptolabs_proxy import auth


LTX_URL = "https://mfjs9076.cloud.netboxapp.com/"
CHARLOTTE_URL = "https://zwar3729.cloud.netboxapp.com/"


def metadata(client):
    response = client.get("/auth/api/netbox")
    assert response.status_code == 200
    return response.get_json()


def save_link(client, url):
    token = metadata(client)["csrf_token"]
    return client.post("/auth/api/settings", json={"netbox_url": url},
                       headers={"X-CSRF-Token": token})


def test_new_site_has_unconfigured_netbox(logged_in_admin):
    data = metadata(logged_in_admin)
    assert data["configured"] is False
    assert data["url"] == ""
    assert data["can_configure"] is True
    assert data["csrf_token"]
    assert auth.load_settings()["netbox_url"] == ""


def test_metadata_requires_login(client):
    response = client.get("/auth/api/netbox")
    assert response.status_code in (302, 401)


@pytest.mark.parametrize("role", ["readonly", "readwrite"])
def test_other_roles_can_open_but_cannot_configure(client, role):
    auth.create_user("member", "test-password", role)
    client.post("/auth/login", data={"username": "member", "password": "test-password"})
    auth.set_setting("netbox_url", LTX_URL)
    data = metadata(client)
    assert data == {"configured": True, "url": LTX_URL, "can_configure": False}
    response = client.post("/auth/api/settings", json={"netbox_url": CHARLOTTE_URL})
    assert response.status_code == 403
    assert auth.get_setting("netbox_url") == LTX_URL


def test_save_preserves_security_settings_and_restart(logged_in_admin):
    auth.set_setting("session_timeout_hours", 48)
    auth.set_setting("allow_anonymous", False)
    response = save_link(logged_in_admin, LTX_URL)
    assert response.status_code == 200
    assert metadata(logged_in_admin)["url"] == LTX_URL
    assert auth.load_settings()["session_timeout_hours"] == 48
    assert auth.load_settings()["allow_anonymous"] is False
    restarted = auth.create_flask_auth_app().test_client()
    restarted.post("/auth/login", data={"username": "admin", "password": "adminpass"})
    assert metadata(restarted)["url"] == LTX_URL


def test_distinct_sites_keep_distinct_urls(logged_in_admin, tmp_path, monkeypatch):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    first_store = auth.DATA_DIR
    monkeypatch.setattr(auth, "DATA_DIR", tmp_path / "second-site")
    assert save_link(logged_in_admin, CHARLOTTE_URL).status_code == 200
    assert auth.get_setting("netbox_url") == CHARLOTTE_URL
    monkeypatch.setattr(auth, "DATA_DIR", first_store)
    assert metadata(logged_in_admin)["url"] == LTX_URL


def test_clear_returns_site_to_unconfigured(logged_in_admin):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    assert save_link(logged_in_admin, "").status_code == 200
    assert metadata(logged_in_admin)["configured"] is False
    assert metadata(logged_in_admin)["url"] == ""


def test_omitted_url_preserves_saved_link(logged_in_admin):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    response = logged_in_admin.post("/auth/api/settings", json={"session_timeout_hours": 72})
    assert response.status_code == 200
    assert metadata(logged_in_admin)["url"] == LTX_URL


@pytest.mark.parametrize("value", [
    None, 123, True, [], {}, "javascript:alert(1)", "data:text/html,test",
    "//netbox.example/", "/netbox/", "https://", "https://user:password@netbox.example/",
    "https://user@netbox.example/", "https://netbox.example:bad/",
    "https://netbox.example:70000/", "https://netbox.example/\nwrong",
    "https://netbox.example/\twrong", "https://netbox.example\\@evil.example/",
    "https://netbox example/", "https://netbox.example/" + "a" * 2050,
])
def test_invalid_api_write_preserves_entire_configuration(logged_in_admin, value):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    before = auth.get_settings_file().read_bytes()
    token = metadata(logged_in_admin)["csrf_token"]
    response = logged_in_admin.post("/auth/api/settings", json={
        "netbox_url": value, "session_timeout_hours": 7,
    }, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    assert auth.get_settings_file().read_bytes() == before


@pytest.mark.parametrize("value", [LTX_URL, "http://netbox.internal:8000/netbox/",
                                  'https://netbox.example/dcim/?q="rack"&site=2'])
def test_valid_url_retains_destination(logged_in_admin, value):
    assert save_link(logged_in_admin, "  " + value + "  ").status_code == 200
    assert metadata(logged_in_admin)["url"] == value


def test_missing_or_wrong_csrf_does_not_save(logged_in_admin):
    metadata(logged_in_admin)
    for headers in ({}, {"X-CSRF-Token": "wrong"}, {"X-CSRF-Token": "☃"}):
        response = logged_in_admin.post("/auth/api/settings", json={"netbox_url": LTX_URL},
                                        headers=headers)
        assert response.status_code == 403
    assert auth.get_setting("netbox_url") == ""


def test_settings_form_has_separate_netbox_setup(logged_in_admin):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    page = logged_in_admin.get("/auth/settings").get_data(as_text=True)
    assert 'id="netbox"' in page
    assert 'name="netbox_url"' in page
    assert 'name="netbox_csrf_token"' in page
    assert "Save NetBox" in page
    assert "Remove NetBox" in page


def test_netbox_form_preserves_security_settings(logged_in_admin):
    auth.set_setting("session_timeout_hours", 48)
    token = metadata(logged_in_admin)["csrf_token"]
    response = logged_in_admin.post("/auth/settings", data={
        "settings_section": "netbox", "netbox_url": LTX_URL, "netbox_csrf_token": token,
    })
    assert response.status_code == 200
    assert metadata(logged_in_admin)["url"] == LTX_URL
    assert auth.get_setting("session_timeout_hours") == 48


def test_netbox_form_remove_clears_saved_url(logged_in_admin):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    token = metadata(logged_in_admin)["csrf_token"]
    response = logged_in_admin.post("/auth/settings", data={
        "settings_section": "netbox", "netbox_url": LTX_URL,
        "netbox_action": "remove", "netbox_csrf_token": token,
    })
    assert response.status_code == 200
    assert metadata(logged_in_admin)["configured"] is False


def test_invalid_form_shows_error_without_changing_settings(logged_in_admin):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    before = auth.get_settings_file().read_bytes()
    token = metadata(logged_in_admin)["csrf_token"]
    response = logged_in_admin.post("/auth/settings", data={
        "settings_section": "netbox", "netbox_url": "javascript:alert(1)",
        "netbox_csrf_token": token,
    })
    assert response.status_code == 400
    assert "HTTP or HTTPS" in response.get_data(as_text=True)
    assert auth.get_settings_file().read_bytes() == before


def test_bad_stored_url_never_becomes_open_link(logged_in_admin):
    auth.set_setting("netbox_url", "javascript:alert(1)")
    data = metadata(logged_in_admin)
    assert data["configured"] is False
    assert data["url"] == ""


def test_non_object_settings_payload_is_rejected(logged_in_admin):
    assert logged_in_admin.post("/auth/api/settings", json=[]).status_code == 400


def test_landing_page_contains_configurable_netbox_card():
    page = (Path(__file__).parents[1] / "landing-page/index.html").read_text()
    assert "'netbox':" in page
    assert "/auth/api/netbox" in page
    assert "Set up NetBox" in page
    assert "Open NetBox" in page
    assert "/auth/settings#netbox" in page
    assert 'rel="noopener noreferrer"' in page


@pytest.mark.parametrize("token", [None, "wrong"])
def test_netbox_form_rejects_missing_or_wrong_csrf(logged_in_admin, token):
    before = auth.load_settings()
    response = logged_in_admin.post("/auth/settings", data={
        "settings_section": "netbox", "netbox_url": LTX_URL,
        **({"netbox_csrf_token": token} if token else {}),
    })
    assert response.status_code == 403
    assert auth.load_settings() == before


def test_readonly_cannot_submit_netbox_form(logged_in_readonly):
    response = logged_in_readonly.post("/auth/settings", data={
        "settings_section": "netbox", "netbox_url": LTX_URL,
    })
    assert response.status_code == 403
    assert auth.get_setting("netbox_url") == ""


def test_settings_save_failure_preserves_old_file(logged_in_admin, monkeypatch):
    assert save_link(logged_in_admin, LTX_URL).status_code == 200
    before = auth.get_settings_file().read_bytes()
    def fail_replace(*args):
        raise OSError("test disk error")
    monkeypatch.setattr(auth.os, "replace", fail_replace)
    response = save_link(logged_in_admin, CHARLOTTE_URL)
    assert response.status_code == 503
    assert auth.get_settings_file().read_bytes() == before


def test_form_save_failure_is_truthful(logged_in_admin, monkeypatch):
    token = metadata(logged_in_admin)["csrf_token"]
    def fail_save(*args):
        raise OSError("test disk error")
    monkeypatch.setattr(auth, "save_settings", fail_save)
    response = logged_in_admin.post("/auth/settings", data={
        "settings_section": "netbox", "netbox_url": LTX_URL, "netbox_csrf_token": token,
    })
    assert response.status_code == 503
    assert "could not be saved" in response.get_data(as_text=True)
    assert auth.get_setting("netbox_url") == ""
