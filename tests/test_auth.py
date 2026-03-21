"""Tests for token management, user CRUD, permissions, and account lockout."""

import time
import json
from datetime import datetime, timedelta

import pytest


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

class TestGenerateAuthToken:
    def test_returns_tuple_of_token_and_expiry(self):
        import cryptolabs_proxy.auth as auth

        token, expiry = auth.generate_auth_token('alice', 'admin')
        assert isinstance(token, str)
        assert isinstance(expiry, int)
        assert expiry > int(time.time())

    def test_token_encodes_username_and_role(self):
        import cryptolabs_proxy.auth as auth
        import base64

        token, _ = auth.generate_auth_token('bob', 'readwrite')
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        assert 'bob' in decoded
        assert 'readwrite' in decoded

    def test_different_users_produce_different_tokens(self):
        import cryptolabs_proxy.auth as auth

        t1, _ = auth.generate_auth_token('alice', 'admin')
        t2, _ = auth.generate_auth_token('bob', 'admin')
        assert t1 != t2

    def test_expiry_matches_configured_hours(self, monkeypatch):
        import cryptolabs_proxy.auth as auth

        monkeypatch.setattr(auth, 'AUTH_TOKEN_EXPIRY_HOURS', 2)
        _, expiry = auth.generate_auth_token('alice', 'admin')
        expected = int(time.time()) + 2 * 3600
        assert abs(expiry - expected) <= 2  # allow 2s drift


class TestVerifyAuthToken:
    def test_valid_token_returns_dict(self):
        import cryptolabs_proxy.auth as auth

        token, _ = auth.generate_auth_token('alice', 'admin')
        result = auth.verify_auth_token(token)
        assert result is not None
        assert result['username'] == 'alice'
        assert result['role'] == 'admin'

    def test_expired_token_returns_none(self, monkeypatch):
        import cryptolabs_proxy.auth as auth

        monkeypatch.setattr(auth, 'AUTH_TOKEN_EXPIRY_HOURS', 0)
        # Generate with 0 hours -> already expired (or at boundary)
        token, _ = auth.generate_auth_token('alice', 'admin')
        # Force expiry by sleeping a tiny bit is unreliable; instead
        # monkey-patch time to simulate future
        original_time = time.time
        monkeypatch.setattr(time, 'time', lambda: original_time() + 10)
        assert auth.verify_auth_token(token) is None

    def test_tampered_token_returns_none(self):
        import cryptolabs_proxy.auth as auth
        import base64

        token, _ = auth.generate_auth_token('alice', 'admin')
        # Tamper with the payload
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        tampered = decoded.replace('alice', 'evil')
        tampered_token = base64.urlsafe_b64encode(tampered.encode()).decode()
        assert auth.verify_auth_token(tampered_token) is None

    def test_garbage_token_returns_none(self):
        import cryptolabs_proxy.auth as auth

        assert auth.verify_auth_token('not-a-real-token!!') is None
        assert auth.verify_auth_token('') is None

    def test_wrong_secret_returns_none(self, monkeypatch):
        import cryptolabs_proxy.auth as auth

        token, _ = auth.generate_auth_token('alice', 'admin')
        monkeypatch.setattr(auth, 'AUTH_SECRET_KEY', 'different-secret')
        assert auth.verify_auth_token(token) is None


class TestGenerateProxyHeaders:
    def test_returns_all_expected_headers(self):
        import cryptolabs_proxy.auth as auth

        headers = auth.generate_proxy_headers('alice', 'admin')
        assert auth.AUTH_HEADER_USER in headers
        assert auth.AUTH_HEADER_ROLE in headers
        assert auth.AUTH_HEADER_TOKEN in headers
        assert auth.AUTH_HEADER_TIMESTAMP in headers
        assert headers[auth.AUTH_HEADER_USER] == 'alice'
        assert headers[auth.AUTH_HEADER_ROLE] == 'admin'


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

class TestCreateUser:
    def test_create_returns_true(self):
        import cryptolabs_proxy.auth as auth

        assert auth.create_user('alice', 'pass123', 'admin') is True

    def test_duplicate_returns_false(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123', 'admin')
        assert auth.create_user('alice', 'other', 'admin') is False

    def test_invalid_role_defaults_to_readonly(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123', 'superuser')
        user = auth.get_user('alice')
        assert user['role'] == 'readonly'

    def test_user_fields_populated(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123', 'readwrite', enabled=True,
                         require_password_change=True)
        user = auth.get_user('alice')
        assert user['username'] == 'alice'
        assert user['role'] == 'readwrite'
        assert user['enabled'] is True
        assert user['require_password_change'] is True
        assert user['created_at'] is not None
        assert user['last_login'] is None
        assert user['login_attempts'] == 0
        assert user['locked_until'] is None


class TestGetUser:
    def test_existing_user(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123')
        user = auth.get_user('alice')
        assert user is not None
        assert user['username'] == 'alice'

    def test_nonexistent_user_returns_none(self):
        import cryptolabs_proxy.auth as auth

        assert auth.get_user('ghost') is None


class TestListUsers:
    def test_empty_when_no_users(self):
        import cryptolabs_proxy.auth as auth

        assert auth.list_users() == []

    def test_lists_all_users_without_password_hash(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123', 'admin')
        auth.create_user('bob', 'pass456', 'readonly')
        users = auth.list_users()
        assert len(users) == 2
        usernames = {u['username'] for u in users}
        assert usernames == {'alice', 'bob'}
        for u in users:
            assert 'password_hash' not in u


class TestUpdateUser:
    def test_update_role(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123', 'readonly')
        assert auth.update_user('alice', role='admin') is True
        assert auth.get_user('alice')['role'] == 'admin'

    def test_update_enabled(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123')
        assert auth.update_user('alice', enabled=False) is True
        assert auth.get_user('alice')['enabled'] is False

    def test_update_nonexistent_returns_false(self):
        import cryptolabs_proxy.auth as auth

        assert auth.update_user('ghost', role='admin') is False

    def test_invalid_role_ignored(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass123', 'readonly')
        auth.update_user('alice', role='superuser')
        assert auth.get_user('alice')['role'] == 'readonly'


class TestDeleteUser:
    def test_delete_existing(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('admin1', 'pass', 'admin')
        auth.create_user('bob', 'pass', 'readonly')
        assert auth.delete_user('bob') is True
        assert auth.get_user('bob') is None

    def test_delete_nonexistent_returns_false(self):
        import cryptolabs_proxy.auth as auth

        assert auth.delete_user('ghost') is False

    def test_cannot_delete_last_admin(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('admin1', 'pass', 'admin')
        assert auth.delete_user('admin1') is False
        assert auth.get_user('admin1') is not None

    def test_can_delete_admin_when_others_exist(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('admin1', 'pass', 'admin')
        auth.create_user('admin2', 'pass', 'admin')
        assert auth.delete_user('admin1') is True

    def test_disabled_admin_not_counted_as_active(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('admin1', 'pass', 'admin')
        auth.create_user('admin2', 'pass', 'admin')
        auth.update_user('admin2', enabled=False)
        # admin1 is the only enabled admin -> cannot delete
        assert auth.delete_user('admin1') is False


class TestVerifyUser:
    def test_correct_credentials(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'secret', 'admin')
        result = auth.verify_user('alice', 'secret')
        assert result is not None
        assert result['username'] == 'alice'
        assert result['role'] == 'admin'

    def test_wrong_password(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'secret')
        assert auth.verify_user('alice', 'wrong') is None

    def test_nonexistent_user(self):
        import cryptolabs_proxy.auth as auth

        assert auth.verify_user('ghost', 'pass') is None

    def test_disabled_user_cannot_login(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'secret')
        auth.update_user('alice', enabled=False)
        assert auth.verify_user('alice', 'secret') is None

    def test_successful_login_resets_attempts(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'secret', 'admin')
        # Fail once
        auth.verify_user('alice', 'wrong')
        user = auth.get_user('alice')
        assert user['login_attempts'] == 1
        # Succeed
        auth.verify_user('alice', 'secret')
        user = auth.get_user('alice')
        assert user['login_attempts'] == 0

    def test_successful_login_updates_last_login(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'secret', 'admin')
        assert auth.get_user('alice')['last_login'] is None
        auth.verify_user('alice', 'secret')
        assert auth.get_user('alice')['last_login'] is not None


class TestChangePassword:
    def test_successful_change(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'oldpass', 'admin')
        assert auth.change_password('alice', 'oldpass', 'newpass') is True
        # Old password no longer works
        assert auth.verify_user('alice', 'oldpass') is None
        # New password works
        assert auth.verify_user('alice', 'newpass') is not None

    def test_wrong_old_password(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'oldpass')
        assert auth.change_password('alice', 'wrongold', 'newpass') is False

    def test_clears_require_password_change_flag(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'oldpass', require_password_change=True)
        auth.change_password('alice', 'oldpass', 'newpass')
        user = auth.get_user('alice')
        assert user['require_password_change'] is False

    def test_nonexistent_user(self):
        import cryptolabs_proxy.auth as auth

        assert auth.change_password('ghost', 'a', 'b') is False


class TestAdminSetPassword:
    def test_sets_password_and_forces_change(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'oldpass')
        assert auth.admin_set_password('alice', 'newpass') is True
        user = auth.get_user('alice')
        assert user['require_password_change'] is True
        # New password works
        assert auth.verify_user('alice', 'newpass') is not None

    def test_nonexistent_user(self):
        import cryptolabs_proxy.auth as auth

        assert auth.admin_set_password('ghost', 'pass') is False


# ---------------------------------------------------------------------------
# Account lockout
# ---------------------------------------------------------------------------

class TestAccountLockout:
    def test_lockout_after_max_attempts(self, monkeypatch):
        import cryptolabs_proxy.auth as auth

        # Set max attempts low for testing
        auth.save_settings({'max_login_attempts': 3, 'lockout_duration_minutes': 15})
        auth.create_user('alice', 'secret', 'admin')

        for _ in range(3):
            auth.verify_user('alice', 'wrong')

        user = auth.get_user('alice')
        assert user['locked_until'] is not None
        assert user['login_attempts'] == 3

        # Even correct password fails during lockout
        assert auth.verify_user('alice', 'secret') is None

    def test_lockout_expires(self, monkeypatch):
        import cryptolabs_proxy.auth as auth

        auth.save_settings({'max_login_attempts': 2, 'lockout_duration_minutes': 1})
        auth.create_user('alice', 'secret', 'admin')

        auth.verify_user('alice', 'wrong')
        auth.verify_user('alice', 'wrong')
        assert auth.verify_user('alice', 'secret') is None  # locked

        # Simulate lockout expired by setting locked_until in the past
        users = auth.load_users()
        users['alice']['locked_until'] = (
            datetime.utcnow() - timedelta(minutes=5)
        ).isoformat()
        auth.save_users(users)

        # Now login should work
        result = auth.verify_user('alice', 'secret')
        assert result is not None
        assert result['username'] == 'alice'


# ---------------------------------------------------------------------------
# Permission helpers
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_has_permission_hierarchy(self):
        import cryptolabs_proxy.auth as auth

        # Admin can do everything
        assert auth.has_permission('admin', 'admin') is True
        assert auth.has_permission('admin', 'readwrite') is True
        assert auth.has_permission('admin', 'readonly') is True

        # readwrite can do readwrite and below
        assert auth.has_permission('readwrite', 'admin') is False
        assert auth.has_permission('readwrite', 'readwrite') is True
        assert auth.has_permission('readwrite', 'readonly') is True

        # readonly
        assert auth.has_permission('readonly', 'admin') is False
        assert auth.has_permission('readonly', 'readwrite') is False
        assert auth.has_permission('readonly', 'readonly') is True

        # anonymous
        assert auth.has_permission('anonymous', 'readonly') is False
        assert auth.has_permission('anonymous', 'anonymous') is True

    def test_can_admin(self):
        import cryptolabs_proxy.auth as auth

        assert auth.can_admin('admin') is True
        assert auth.can_admin('readwrite') is False
        assert auth.can_admin('readonly') is False

    def test_can_write(self):
        import cryptolabs_proxy.auth as auth

        assert auth.can_write('admin') is True
        assert auth.can_write('readwrite') is True
        assert auth.can_write('readonly') is False

    def test_can_read(self):
        import cryptolabs_proxy.auth as auth

        assert auth.can_read('admin') is True
        assert auth.can_read('readwrite') is True
        assert auth.can_read('readonly') is True
        assert auth.can_read('anonymous') is False

    def test_unknown_role_gets_zero_level(self):
        import cryptolabs_proxy.auth as auth

        assert auth.has_permission('unknown_role', 'readonly') is False


# ---------------------------------------------------------------------------
# Settings management
# ---------------------------------------------------------------------------

class TestSettings:
    def test_defaults_returned_when_no_file(self):
        import cryptolabs_proxy.auth as auth

        settings = auth.load_settings()
        assert settings['allow_anonymous'] is False
        assert settings['max_login_attempts'] == 5
        assert settings['lockout_duration_minutes'] == 15
        assert settings['session_timeout_hours'] == 24

    def test_save_and_load(self):
        import cryptolabs_proxy.auth as auth

        auth.save_settings({'allow_anonymous': True, 'max_login_attempts': 10})
        settings = auth.load_settings()
        assert settings['allow_anonymous'] is True
        assert settings['max_login_attempts'] == 10
        # Defaults still present for keys not saved
        assert 'session_timeout_hours' in settings

    def test_get_setting(self):
        import cryptolabs_proxy.auth as auth

        assert auth.get_setting('max_login_attempts') == 5
        assert auth.get_setting('nonexistent', 'fallback') == 'fallback'

    def test_set_setting(self):
        import cryptolabs_proxy.auth as auth

        auth.set_setting('max_login_attempts', 99)
        assert auth.get_setting('max_login_attempts') == 99


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_user_exists_false_initially(self):
        import cryptolabs_proxy.auth as auth

        assert auth.user_exists() is False

    def test_user_exists_true_after_create(self):
        import cryptolabs_proxy.auth as auth

        auth.create_user('alice', 'pass')
        assert auth.user_exists() is True

    def test_get_admin_count(self):
        import cryptolabs_proxy.auth as auth

        assert auth.get_admin_count() == 0
        auth.create_user('a1', 'p', 'admin')
        assert auth.get_admin_count() == 1
        auth.create_user('a2', 'p', 'admin')
        assert auth.get_admin_count() == 2
        auth.update_user('a2', enabled=False)
        assert auth.get_admin_count() == 1


class TestVerifyProxyAuth:
    def test_valid_headers(self):
        import cryptolabs_proxy.auth as auth

        headers = auth.generate_proxy_headers('alice', 'admin')
        result = auth.verify_proxy_auth(headers)
        assert result is not None
        assert result['username'] == 'alice'
        assert result['role'] == 'admin'
        assert result['authenticated_via'] == 'fleet_proxy'

    def test_missing_token(self):
        import cryptolabs_proxy.auth as auth

        assert auth.verify_proxy_auth({}) is None

    def test_mismatched_username(self):
        import cryptolabs_proxy.auth as auth

        headers = auth.generate_proxy_headers('alice', 'admin')
        headers[auth.AUTH_HEADER_USER] = 'eve'
        assert auth.verify_proxy_auth(headers) is None
