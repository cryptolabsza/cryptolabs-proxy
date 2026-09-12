"""Tests for Flask routes: login/logout, user management, settings, API endpoints."""

import hashlib
import hmac
import json
from datetime import timedelta
import pytest


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

class TestLoginRoute:
    def test_get_login_page(self, client):
        resp = client.get('/auth/login')
        assert resp.status_code == 200
        assert b'Fleet Management' in resp.data

    def test_first_run_shows_setup(self, client):
        """When no users exist, login page should show first-run setup."""
        resp = client.get('/auth/login')
        assert b'Create your admin account' in resp.data

    def test_first_run_create_account(self, client):
        resp = client.post('/auth/login', data={
            'username': 'admin',
            'password': 'testpass',
            'confirm_password': 'testpass',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers['Location'] == '/'

        # User was created
        import cryptolabs_proxy.auth as auth
        assert auth.get_user('admin') is not None

    def test_first_run_password_mismatch(self, client):
        resp = client.post('/auth/login', data={
            'username': 'admin',
            'password': 'testpass',
            'confirm_password': 'different',
        })
        assert resp.status_code == 200
        assert b'Passwords do not match' in resp.data

    def test_first_run_short_password(self, client):
        resp = client.post('/auth/login', data={
            'username': 'admin',
            'password': 'abc',
            'confirm_password': 'abc',
        })
        assert resp.status_code == 200
        assert b'at least 4 characters' in resp.data

    def test_normal_login_success(self, client, admin_user):
        resp = client.post('/auth/login', data={
            'username': admin_user['username'],
            'password': admin_user['password'],
        }, follow_redirects=False)
        assert resp.status_code == 302

    def test_normal_login_invalid_credentials(self, client, admin_user):
        resp = client.post('/auth/login', data={
            'username': admin_user['username'],
            'password': 'wrongpass',
        })
        assert resp.status_code == 200
        assert b'Invalid username or password' in resp.data

    def test_login_sets_session(self, client, admin_user):
        with client.session_transaction() as sess:
            assert 'logged_in' not in sess

        client.post('/auth/login', data={
            'username': admin_user['username'],
            'password': admin_user['password'],
        })

        with client.session_transaction() as sess:
            assert sess['logged_in'] is True
            assert sess['username'] == admin_user['username']
            assert sess['role'] == 'admin'
            assert 'auth_token' in sess

    def test_login_redirects_to_next(self, client, admin_user):
        resp = client.post('/auth/login?next=/dashboard', data={
            'username': admin_user['username'],
            'password': admin_user['password'],
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert '/dashboard' in resp.headers['Location']

    def test_login_redirects_to_change_password_when_required(self, client):
        import cryptolabs_proxy.auth as auth
        auth.create_user('needchange', 'pass123', 'readwrite',
                         require_password_change=True)

        resp = client.post('/auth/login', data={
            'username': 'needchange',
            'password': 'pass123',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert '/auth/change-password' in resp.headers['Location']


class TestLogoutRoute:
    def test_logout_clears_session(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/logout', follow_redirects=False)
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

        with logged_in_admin.session_transaction() as sess:
            assert 'logged_in' not in sess


# ---------------------------------------------------------------------------
# Vast Price Manager Fleet session authority
# ---------------------------------------------------------------------------

class TestVastPriceManagerFleetSession:
    def _login(self, client, admin_user):
        response = client.post('/auth/login', data={
            'username': admin_user['username'],
            'password': admin_user['password'],
        })
        assert response.status_code == 302

    def _vpm_session(self, client):
        """Model VPM's direct call without forwarding Fleet's Set-Cookie back."""
        incoming_cookie = client.get_cookie('fleet_session')
        response = client.get('/auth/vast-price-manager/session')
        if incoming_cookie:
            client.set_cookie('fleet_session', incoming_cookie.value)
        return response

    def test_session_uses_real_fleet_cookie_and_returns_only_contract_fields(self, client, admin_user):
        import cryptolabs_proxy.auth as auth

        self._login(client, admin_user)
        signed_cookie = client.get_cookie('fleet_session').value.encode('utf-8')

        response = self._vpm_session(client)

        assert response.status_code == 200
        assert response.get_json() == {
            'authenticated': True,
            'username': admin_user['username'],
            'role': 'admin',
            'subject': response.get_json()['subject'],
            'csrf_token': response.get_json()['csrf_token'],
        }
        payload = response.get_json()
        assert len(payload['subject']) == 64
        assert len(payload['csrf_token']) == 64
        assert payload['subject'] != payload['csrf_token']
        assert all(character in '0123456789abcdef' for character in payload['subject'])
        assert all(character in '0123456789abcdef' for character in payload['csrf_token'])
        assert payload['subject'] == hmac.new(
            auth.AUTH_SECRET_KEY.encode('utf-8'),
            b'cryptolabs/vpm/subject/v1:' + signed_cookie,
            hashlib.sha256,
        ).hexdigest()
        assert payload['csrf_token'] == hmac.new(
            auth.AUTH_SECRET_KEY.encode('utf-8'),
            b'cryptolabs/vpm/csrf/v1:' + signed_cookie,
            hashlib.sha256,
        ).hexdigest()
        assert b'fleet_session=' not in response.data
        assert b'password' not in response.data

    def test_session_rechecks_current_user_state_instead_of_cached_session_role(self, client, admin_user):
        import cryptolabs_proxy.auth as auth

        self._login(client, admin_user)
        auth.update_user(admin_user['username'], role='readonly')

        assert client.get('/auth/vast-price-manager/session').status_code == 403
        assert client.get('/auth/vast-price-manager/authorize').status_code == 403

    @pytest.mark.parametrize('change', [
        lambda auth, username: auth.update_user(username, enabled=False),
        lambda auth, username: auth.update_user(username, require_password_change=True),
        lambda auth, username: auth.delete_user(username),
    ])
    def test_session_rejects_disabled_forced_change_or_deleted_user(self, client, admin_user, change):
        import cryptolabs_proxy.auth as auth

        # Keep a second admin so the delete operation is valid.
        auth.create_user('other-admin', 'otherpass', role='admin')
        self._login(client, admin_user)
        change(auth, admin_user['username'])

        expected = 401 if auth.get_user(admin_user['username']) and auth.get_user(admin_user['username']).get('require_password_change') else 403
        assert client.get('/auth/vast-price-manager/session').status_code == expected

    def test_session_requires_a_signed_logged_in_fleet_session(self, client, admin_user):
        assert client.get('/auth/vast-price-manager/session').status_code == 401
        client.set_cookie('fleet_session', 'forged-session')
        assert client.get('/auth/vast-price-manager/session').status_code == 401

    def test_session_rejects_an_expired_signed_fleet_session(self, client, admin_user):
        self._login(client, admin_user)
        client.application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=-1)

        assert client.get('/auth/vast-price-manager/session').status_code == 401

    def test_reauth_validates_csrf_and_current_fleet_password(self, client, admin_user):
        self._login(client, admin_user)
        session = self._vpm_session(client).get_json()

        invalid_csrf = client.post('/auth/vast-price-manager/reauth', json={
            'password': admin_user['password'], 'csrf_token': '0' * 64,
        })
        assert invalid_csrf.status_code == 403

        wrong_password = client.post('/auth/vast-price-manager/reauth', json={
            'password': 'incorrect', 'csrf_token': session['csrf_token'],
        })
        assert wrong_password.status_code == 401

        session = self._vpm_session(client).get_json()
        valid = client.post('/auth/vast-price-manager/reauth', json={
            'password': admin_user['password'], 'csrf_token': session['csrf_token'],
        })
        assert valid.status_code == 200
        assert valid.get_json() == session

    def test_reauth_rejects_unbounded_or_non_json_input(self, client, admin_user):
        self._login(client, admin_user)
        session = client.get('/auth/vast-price-manager/session').get_json()

        assert client.post('/auth/vast-price-manager/reauth', data='not-json').status_code == 400
        assert client.post('/auth/vast-price-manager/reauth', json={
            'password': 'x' * 4097, 'csrf_token': session['csrf_token'],
        }).status_code == 400

    def test_reauth_reports_detectable_password_throttling(self, client, admin_user):
        import cryptolabs_proxy.auth as auth

        auth.save_settings({'max_login_attempts': 3, 'lockout_duration_minutes': 15})
        self._login(client, admin_user)
        for _ in range(2):
            csrf_token = self._vpm_session(client).get_json()['csrf_token']
            assert client.post('/auth/vast-price-manager/reauth', json={
                'password': 'incorrect', 'csrf_token': csrf_token,
            }).status_code == 401

        csrf_token = self._vpm_session(client).get_json()['csrf_token']
        limited = client.post('/auth/vast-price-manager/reauth', json={
            'password': 'incorrect', 'csrf_token': csrf_token,
        })
        assert limited.status_code == 429

    def test_reauth_rechecks_live_user_state(self, client, admin_user):
        import cryptolabs_proxy.auth as auth

        self._login(client, admin_user)
        csrf_token = self._vpm_session(client).get_json()['csrf_token']
        auth.update_user(admin_user['username'], enabled=False)

        response = client.post('/auth/vast-price-manager/reauth', json={
            'password': admin_user['password'], 'csrf_token': csrf_token,
        })
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Change password route
# ---------------------------------------------------------------------------

class TestChangePasswordRoute:
    def test_requires_login(self, client):
        resp = client.get('/auth/change-password', follow_redirects=False)
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_get_form(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/change-password')
        assert resp.status_code == 200

    def test_successful_change(self, logged_in_admin, admin_user):
        resp = logged_in_admin.post('/auth/change-password', data={
            'current_password': admin_user['password'],
            'new_password': 'newpass123',
            'confirm_password': 'newpass123',
        }, follow_redirects=False)
        assert resp.status_code == 302

        # Verify new password works
        import cryptolabs_proxy.auth as auth
        assert auth.verify_user(admin_user['username'], 'newpass123') is not None

    def test_wrong_current_password(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/change-password', data={
            'current_password': 'wrongpass',
            'new_password': 'newpass123',
            'confirm_password': 'newpass123',
        })
        assert resp.status_code == 200
        assert b'Current password is incorrect' in resp.data

    def test_short_new_password(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/change-password', data={
            'current_password': 'adminpass',
            'new_password': 'abc',
            'confirm_password': 'abc',
        })
        assert resp.status_code == 200
        assert b'at least 4 characters' in resp.data

    def test_mismatched_confirm(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/change-password', data={
            'current_password': 'adminpass',
            'new_password': 'newpass123',
            'confirm_password': 'different',
        })
        assert resp.status_code == 200
        assert b'Passwords do not match' in resp.data


# ---------------------------------------------------------------------------
# User management routes (admin only)
# ---------------------------------------------------------------------------

class TestUsersListRoute:
    def test_requires_admin(self, logged_in_readonly):
        resp = logged_in_readonly.get('/auth/users')
        assert resp.status_code == 403

    def test_admin_can_access(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/users')
        assert resp.status_code == 200
        assert b'User Management' in resp.data

    def test_unauthenticated_redirects(self, client):
        resp = client.get('/auth/users', follow_redirects=False)
        assert resp.status_code == 302


class TestUsersCreateRoute:
    def test_create_user(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/users/create', data={
            'username': 'newuser',
            'password': 'newpass',
            'role': 'readonly',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'success' in resp.headers['Location']

        import cryptolabs_proxy.auth as auth
        user = auth.get_user('newuser')
        assert user is not None
        assert user['role'] == 'readonly'
        assert user['require_password_change'] is True  # forced on create via route

    def test_create_duplicate(self, logged_in_admin, admin_user):
        resp = logged_in_admin.post('/auth/users/create', data={
            'username': admin_user['username'],
            'password': 'pass',
            'role': 'readonly',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']

    def test_missing_fields(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/users/create', data={
            'username': '',
            'password': '',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']


class TestUsersToggleRoute:
    def test_toggle_user(self, logged_in_admin):
        import cryptolabs_proxy.auth as auth
        auth.create_user('target', 'pass', 'readonly')
        assert auth.get_user('target')['enabled'] is True

        logged_in_admin.post('/auth/users/target/toggle')
        assert auth.get_user('target')['enabled'] is False

        logged_in_admin.post('/auth/users/target/toggle')
        assert auth.get_user('target')['enabled'] is True

    def test_toggle_nonexistent_user(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/users/ghost/toggle',
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']


class TestUsersDeleteRoute:
    def test_delete_user(self, logged_in_admin):
        import cryptolabs_proxy.auth as auth
        auth.create_user('target', 'pass', 'readonly')

        resp = logged_in_admin.post('/auth/users/target/delete',
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'success' in resp.headers['Location']
        assert auth.get_user('target') is None

    def test_cannot_delete_last_admin(self, logged_in_admin, admin_user):
        resp = logged_in_admin.post(
            f'/auth/users/{admin_user["username"]}/delete',
            follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']


class TestUsersResetPasswordRoute:
    def test_reset_password(self, logged_in_admin):
        import cryptolabs_proxy.auth as auth
        auth.create_user('target', 'oldpass', 'readonly')

        resp = logged_in_admin.post('/auth/users/target/reset-password',
                                     data={'new_password': 'newpass123'},
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'success' in resp.headers['Location']

        assert auth.verify_user('target', 'newpass123') is not None
        assert auth.get_user('target')['require_password_change'] is True

    def test_short_password_rejected(self, logged_in_admin):
        import cryptolabs_proxy.auth as auth
        auth.create_user('target', 'oldpass', 'readonly')

        resp = logged_in_admin.post('/auth/users/target/reset-password',
                                     data={'new_password': 'ab'},
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']

    def test_nonexistent_user(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/users/ghost/reset-password',
                                     data={'new_password': 'newpass'},
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']


class TestUsersChangeRoleRoute:
    def test_change_role(self, logged_in_admin):
        import cryptolabs_proxy.auth as auth
        auth.create_user('target', 'pass', 'readonly')

        resp = logged_in_admin.post('/auth/users/target/role',
                                     data={'role': 'readwrite'},
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'success' in resp.headers['Location']
        assert auth.get_user('target')['role'] == 'readwrite'

    def test_cannot_change_own_role(self, logged_in_admin, admin_user):
        resp = logged_in_admin.post(
            f'/auth/users/{admin_user["username"]}/role',
            data={'role': 'readonly'},
            follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']

    def test_invalid_role(self, logged_in_admin):
        import cryptolabs_proxy.auth as auth
        auth.create_user('target', 'pass', 'readonly')

        resp = logged_in_admin.post('/auth/users/target/role',
                                     data={'role': 'superuser'},
                                     follow_redirects=False)
        assert resp.status_code == 302
        assert 'error' in resp.headers['Location']


# ---------------------------------------------------------------------------
# Settings route
# ---------------------------------------------------------------------------

class TestSettingsRoute:
    def test_requires_admin(self, logged_in_readonly):
        resp = logged_in_readonly.get('/auth/settings')
        assert resp.status_code == 403

    def test_get_settings_page(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/settings')
        assert resp.status_code == 200

    def test_save_settings(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/settings', data={
            'allow_anonymous': 'on',
            'anonymous_role': 'readonly',
            'session_timeout_hours': '48',
            'max_login_attempts': '10',
            'lockout_duration_minutes': '30',
        })
        assert resp.status_code == 200
        assert b'Settings saved' in resp.data

        import cryptolabs_proxy.auth as auth
        settings = auth.load_settings()
        assert settings['allow_anonymous'] is True
        assert settings['session_timeout_hours'] == 48
        assert settings['max_login_attempts'] == 10


# ---------------------------------------------------------------------------
# API endpoints: /auth/check, /auth/token, /auth/headers
# ---------------------------------------------------------------------------

class TestAuthCheck:
    def test_authenticated_user(self, logged_in_admin, admin_user):
        resp = logged_in_admin.get('/auth/check')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['authenticated'] is True
        assert data['username'] == admin_user['username']
        assert data['role'] == 'admin'

    def test_unauthenticated(self, client):
        resp = client.get('/auth/check')
        assert resp.status_code == 401
        data = resp.get_json()
        assert data['authenticated'] is False

    def test_anonymous_when_allowed(self, client):
        import cryptolabs_proxy.auth as auth
        auth.save_settings({'allow_anonymous': True, 'anonymous_role': 'readonly'})

        resp = client.get('/auth/check')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['authenticated'] is True
        assert data['username'] == 'anonymous'
        assert data['role'] == 'readonly'


class TestAuthToken:
    def test_authenticated_user_gets_token(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/token')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'token' in data
        assert data['username'] == 'admin'
        assert data['role'] == 'admin'

    def test_unauthenticated_returns_401(self, client):
        resp = client.get('/auth/token')
        assert resp.status_code == 401

    def test_anonymous_token_when_allowed(self, client):
        import cryptolabs_proxy.auth as auth
        auth.save_settings({'allow_anonymous': True, 'anonymous_role': 'readonly'})

        resp = client.get('/auth/token')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['username'] == 'anonymous'

    def test_token_refresh_when_expired(self, logged_in_admin, monkeypatch):
        """If the stored token is invalid, a new one should be generated."""
        # Corrupt the session token
        with logged_in_admin.session_transaction() as sess:
            sess['auth_token'] = 'invalid-token'

        resp = logged_in_admin.get('/auth/token')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'token' in data
        # Token should now be valid
        import cryptolabs_proxy.auth as auth
        assert auth.verify_auth_token(data['token']) is not None


class TestAuthHeaders:
    def test_authenticated_user_gets_headers(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/headers')
        assert resp.status_code == 200
        assert 'X-Fleet-Auth-User' in resp.headers
        assert 'X-Fleet-Auth-Role' in resp.headers
        assert 'X-Fleet-Auth-Token' in resp.headers

    def test_unauthenticated_returns_401(self, client):
        resp = client.get('/auth/headers')
        assert resp.status_code == 401

    def test_anonymous_headers_when_allowed(self, client):
        import cryptolabs_proxy.auth as auth
        auth.save_settings({'allow_anonymous': True, 'anonymous_role': 'readonly'})

        resp = client.get('/auth/headers')
        assert resp.status_code == 200
        assert resp.headers['X-Fleet-Auth-User'] == 'anonymous'
        assert resp.headers['X-Fleet-Auth-Role'] == 'readonly'

    def test_require_password_change_returns_401(self, client):
        import cryptolabs_proxy.auth as auth
        auth.create_user('needchange', 'pass123', 'admin',
                         require_password_change=True)
        client.post('/auth/login', data={
            'username': 'needchange',
            'password': 'pass123',
        })

        resp = client.get('/auth/headers')
        assert resp.status_code == 401

    def test_token_refresh_on_expired_session_token(self, logged_in_admin):
        """If session token is expired/invalid, headers route regenerates it."""
        with logged_in_admin.session_transaction() as sess:
            sess['auth_token'] = 'bad-token'

        resp = logged_in_admin.get('/auth/headers')
        assert resp.status_code == 200
        assert resp.headers.get('X-Fleet-Auth-Token') is not None

        import cryptolabs_proxy.auth as auth
        token_data = auth.verify_auth_token(resp.headers['X-Fleet-Auth-Token'])
        assert token_data is not None


# ---------------------------------------------------------------------------
# JSON API endpoints
# ---------------------------------------------------------------------------

class TestApiUsersEndpoint:
    def test_list_users(self, logged_in_admin, admin_user):
        resp = logged_in_admin.get('/auth/api/users')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert any(u['username'] == admin_user['username'] for u in data)

    def test_create_user_via_api(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/api/users',
                                     data=json.dumps({
                                         'username': 'apiuser',
                                         'password': 'apipass',
                                         'role': 'readwrite',
                                     }),
                                     content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

        import cryptolabs_proxy.auth as auth
        assert auth.get_user('apiuser') is not None

    def test_create_duplicate_via_api(self, logged_in_admin, admin_user):
        resp = logged_in_admin.post('/auth/api/users',
                                     data=json.dumps({
                                         'username': admin_user['username'],
                                         'password': 'pass',
                                     }),
                                     content_type='application/json')
        assert resp.status_code == 400

    def test_requires_admin(self, logged_in_readonly):
        resp = logged_in_readonly.get('/auth/api/users')
        assert resp.status_code == 403


class TestApiSettingsEndpoint:
    def test_get_settings(self, logged_in_admin):
        resp = logged_in_admin.get('/auth/api/settings')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'max_login_attempts' in data

    def test_update_settings(self, logged_in_admin):
        resp = logged_in_admin.post('/auth/api/settings',
                                     data=json.dumps({
                                         'max_login_attempts': 99,
                                     }),
                                     content_type='application/json')
        assert resp.status_code == 200

        import cryptolabs_proxy.auth as auth
        assert auth.get_setting('max_login_attempts') == 99

    def test_requires_admin(self, logged_in_readonly):
        resp = logged_in_readonly.get('/auth/api/settings')
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_login_page_no_first_run_after_user_exists(self, client, admin_user):
        """After a user exists, first_run setup should not show."""
        resp = client.get('/auth/login')
        assert b'Create your admin account' not in resp.data

    def test_session_cookie_config(self, app):
        assert app.config['SESSION_COOKIE_NAME'] == 'fleet_session'
        assert app.config['SESSION_COOKIE_HTTPONLY'] is True
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
