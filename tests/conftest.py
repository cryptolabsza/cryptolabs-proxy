"""Shared fixtures for cryptolabs-proxy test suite."""

import os
import sys
import pytest

# Ensure the src package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


@pytest.fixture(autouse=True)
def isolate_data_dir(tmp_path, monkeypatch):
    """Redirect DATA_DIR to a temp directory for every test, ensuring isolation."""
    import cryptolabs_proxy.auth as auth_mod

    monkeypatch.setattr(auth_mod, 'DATA_DIR', tmp_path)
    # Also fix the secret key to a stable value so tokens are reproducible
    monkeypatch.setattr(auth_mod, 'AUTH_SECRET_KEY', 'test-secret-key-1234')
    monkeypatch.setattr(auth_mod, 'AUTH_TOKEN_EXPIRY_HOURS', 24)
    yield tmp_path


@pytest.fixture
def app(isolate_data_dir):
    """Create a Flask test app with isolated data dir."""
    import cryptolabs_proxy.auth as auth_mod

    flask_app = auth_mod.create_flask_auth_app()
    flask_app.config['TESTING'] = True
    # Disable CSRF / secure cookies for testing
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SESSION_COOKIE_SECURE'] = False
    return flask_app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def admin_user(isolate_data_dir):
    """Create an admin user and return credentials."""
    import cryptolabs_proxy.auth as auth_mod

    username, password = 'admin', 'adminpass'
    auth_mod.create_user(username, password, role='admin')
    return {'username': username, 'password': password, 'role': 'admin'}


@pytest.fixture
def readonly_user(isolate_data_dir):
    """Create a readonly user and return credentials."""
    import cryptolabs_proxy.auth as auth_mod

    username, password = 'viewer', 'viewerpass'
    auth_mod.create_user(username, password, role='readonly')
    return {'username': username, 'password': password, 'role': 'readonly'}


@pytest.fixture
def readwrite_user(isolate_data_dir):
    """Create a readwrite user and return credentials."""
    import cryptolabs_proxy.auth as auth_mod

    username, password = 'editor', 'editorpass'
    auth_mod.create_user(username, password, role='readwrite')
    return {'username': username, 'password': password, 'role': 'readwrite'}


@pytest.fixture
def logged_in_admin(client, admin_user):
    """Return a client that is already logged in as admin."""
    client.post('/auth/login', data={
        'username': admin_user['username'],
        'password': admin_user['password'],
    })
    return client


@pytest.fixture
def logged_in_readonly(client, readonly_user):
    """Return a client that is already logged in as readonly user."""
    client.post('/auth/login', data={
        'username': readonly_user['username'],
        'password': readonly_user['password'],
    })
    return client
