"""Fleet exporter authority and per-request cookie transport regressions."""
from pathlib import Path
from unittest.mock import Mock

import pytest

from cryptolabs_proxy import auth
from cryptolabs_proxy.config import generate_nginx_config


@pytest.mark.parametrize('scheme,remote,forwarded,secure', [
    ('https', '203.0.113.10', None, True),
    ('http', '127.0.0.1', 'https', True),
    ('http', '::1', 'https', True),
    ('http', '127.0.0.1', 'http', False),
    ('http', '203.0.113.10', 'https', False),
    ('http', '203.0.113.10', None, False),
    ('http', '127.0.0.1', 'https,http', False),
])
@pytest.mark.parametrize('first_run', [False, True])
def test_cookie_transport_uses_tls_or_only_loopback_proxy(scheme, remote, forwarded, secure, first_run):
    # Deliberately avoid the shared app fixture's insecure-cookie override.
    app = auth.create_flask_auth_app()
    app.config['TESTING'] = True
    if not first_run:
        auth.create_user('synthetic-admin', 'synthetic-password', 'admin')
    client = app.test_client()
    options = {'base_url': scheme + '://fleet.example.test',
               'environ_overrides': {'REMOTE_ADDR': remote},
               'headers': {'X-Forwarded-Proto': forwarded} if forwarded else {}}
    response = client.post('/auth/login', data={
        'username': 'synthetic-admin', 'password': 'synthetic-password',
        'confirm_password': 'synthetic-password'}, **options)
    assert response.status_code == 302
    cookie = response.headers['Set-Cookie']
    assert ('; Secure' in cookie) is secure
    assert '; HttpOnly' in cookie and '; SameSite=Lax' in cookie
    logout = client.get('/auth/logout', **options)
    assert ('; Secure' in logout.headers['Set-Cookie']) is secure
    # Choosing transport must never mutate shared app configuration.
    assert app.config['SESSION_COOKIE_SECURE'] is False


@pytest.mark.parametrize('state,status', [
    ('admin', 204), ('readonly', 403), ('readwrite', 403),
    ('demoted', 403), ('disabled', 403), ('deleted', 403),
    ('forced-change', 401), ('session-change', 401), ('signed-out', 401),
])
def test_exporter_authorization_rechecks_live_user_before_token_access(client, monkeypatch, state, status):
    auth.create_user('backup-admin', 'synthetic-password', 'admin')
    auth.create_user('subject', 'synthetic-password', state if state in ('readonly', 'readwrite') else 'admin')
    if state != 'signed-out':
        client.post('/auth/login', data={'username': 'subject', 'password': 'synthetic-password'})
    if state == 'demoted':
        auth.update_user('subject', role='readonly')
    elif state == 'disabled':
        auth.update_user('subject', enabled=False)
    elif state == 'deleted':
        auth.delete_user('subject')
    elif state == 'forced-change':
        auth.update_user('subject', require_password_change=True)
    elif state == 'session-change':
        with client.session_transaction() as session:
            session['require_password_change'] = True
    # Synthetic Docker output: rejecting authority must happen before reading it.
    import subprocess
    token_read = Mock(return_value=Mock(returncode=0, stdout='MGMT_TOKEN=synthetic-management-token\n'))
    monkeypatch.setattr(subprocess, 'run', token_read)
    response = client.get('/auth/exporters/authorize', headers={'X-Fleet-Auth-Role': 'admin'})
    assert response.status_code == status
    if status == 204:
        assert response.headers['X-Mgmt-Token'] == 'synthetic-management-token'
        assert token_read.call_count == 1
    else:
        assert 'X-Mgmt-Token' not in response.headers
        token_read.assert_not_called()


@pytest.mark.parametrize('role', ['admin', 'readonly', 'readwrite'])
def test_generic_auth_headers_do_not_disclose_exporter_management_token(client, monkeypatch, role):
    auth.create_user('subject', 'synthetic-password', role)
    client.post('/auth/login', data={'username': 'subject', 'password': 'synthetic-password'})
    import subprocess
    token_read = Mock(return_value=Mock(returncode=0, stdout='MGMT_TOKEN=synthetic-management-token\n'))
    monkeypatch.setattr(subprocess, 'run', token_read)
    response = client.get('/auth/headers')
    assert response.status_code == 200
    assert 'X-Mgmt-Token' not in response.headers
    token_read.assert_not_called()


@pytest.mark.parametrize('name', ['vastai', 'runpod'])
@pytest.mark.parametrize('action', ['enable', 'disable', 'restart'])
@pytest.mark.parametrize('state,status', [('admin', 200), ('demoted', 403), ('disabled', 403),
                                         ('deleted', 403), ('forced-change', 401), ('readonly', 403),
                                         ('readwrite', 403), ('signed-out', 401)])
def test_exporter_mutation_rejects_stale_authority_without_downstream_effects(client, monkeypatch, name, action, state, status):
    import cryptolabs_proxy.exporter_manager as manager
    effect = Mock(return_value={'success': True})
    monkeypatch.setattr(manager, action + '_exporter', effect)
    auth.create_user('backup-admin', 'synthetic-password', 'admin')
    auth.create_user('subject', 'synthetic-password', state if state in ('readonly', 'readwrite') else 'admin')
    if state != 'signed-out':
        client.post('/auth/login', data={'username': 'subject', 'password': 'synthetic-password'})
    if state == 'demoted':
        auth.update_user('subject', role='readonly')
    elif state == 'disabled':
        auth.update_user('subject', enabled=False)
    elif state == 'deleted':
        auth.delete_user('subject')
    elif state == 'forced-change':
        auth.update_user('subject', require_password_change=True)
    response = client.post('/auth/api/exporters/' + name + '/' + action,
                           json={'api_key': 'synthetic-provider-key'},
                           headers={'X-Fleet-Auth-Role': 'admin'})
    assert response.status_code == status
    if status == 200:
        effect.assert_called_once()
    else:
        effect.assert_not_called()


@pytest.mark.parametrize('letsencrypt', [False, True])
def test_generated_and_bundled_exporter_routes_use_admin_check_and_exact_uri(tmp_path, letsencrypt):
    generate_nginx_config(tmp_path, 'fleet.example.test', letsencrypt=letsencrypt)
    generated = (tmp_path / 'nginx.conf').read_text()
    bundled = (Path(__file__).resolve().parents[1] / 'nginx/nginx.conf').read_text()
    fragment = (Path(__file__).resolve().parents[1] /
                'src/cryptolabs_proxy/templates/exporter-auth-routes.conf.j2').read_text().strip()
    for config in [generated, bundled]:
        assert fragment in config
        public_auth = config.split('location /auth/ {', 1)[1].split('\n        }', 1)[0]
        assert 'proxy_set_header X-Forwarded-Proto $scheme;' in public_auth
        auth_block = config.split('location = /_exporter_admin {', 1)[1].split('\n        }', 1)[0]
        assert 'internal;' in auth_block
        assert '/auth/exporters/authorize;' in auth_block
        assert 'proxy_pass_request_body off;' in auth_block
        assert 'proxy_set_header Cookie $http_cookie;' in auth_block
        for name in ['vastai', 'runpod']:
            block = config.split('location ~ ^/' + name + '-api/(.*)$ {', 1)[1].split('\n        }', 1)[0]
            assert 'auth_request /_exporter_admin;' in block
            assert 'auth_request_set $mgmt_token $upstream_http_x_mgmt_token;' in block
            assert 'proxy_set_header X-Mgmt-Token $mgmt_token;' in block
            assert 'proxy_pass $upstream_' + name + '_api/api/$1$is_args$args;' in block
            assert 'error_page 401 = @login_redirect;' not in block
            assert 'auth_request /_auth_check;' not in block
