# TRACEWEAVER: file-role=pairing-verification; req=REQ-PAIR-004; trace=TRACE-PAIR-004; ver=VER-PAIR-004
# TRACEWEAVER: verifies=VER-PAIR-004; req=REQ-PAIR-004; trace=TRACE-PAIR-004
"""PAIR-20261028-01: real Flask/persistent boundary; only HTTPS is substituted.

The RED wire fixture remains specification-derived. Success envelopes consumed
by the network substitute are copied from actual WordPress handler output.
"""

import copy
import json
import multiprocessing
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests

import cryptolabs_proxy.auth as auth


WIRE = json.loads((Path(__file__).parent / 'fixtures/pairing-wire-v1.json').read_text())
PRODUCER = json.loads((Path(__file__).parent / 'fixtures/pairing-producer-v1.json').read_text())
PREFIX = WIRE['transport']['origin'] + WIRE['transport']['rest_prefix']
CLIENT_ID = 'cryptolabs-dc-controller'
OLD_KEY = 'sk-ipmi-' + 'a' * 48
NEW_KEY = WIRE['success_response']['credential']['api_key']


class Reply:
    """Faithful HTTP response boundary, without substituting client validation."""

    def __init__(self, payload, status=200):
        self.status_code = status
        self.content = json.dumps(payload).encode()
        self.text = self.content.decode()
        self.headers = {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}
        self.payload = payload

    def json(self):
        return copy.deepcopy(self.payload)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


@pytest.fixture
def peer(monkeypatch):
    """Fixed synthetic WP emitter; callbacks expose real in-flight races."""
    class Peer:
        calls = None
        installation_id = None
        status_payload = None
        status_code = 200
        on_status = None

        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            assert kwargs.get('verify', True) is not False
            assert kwargs.get('allow_redirects') is False
            assert kwargs.get('timeout')
            if url == PREFIX + '/pairing/start':
                body = kwargs['json']
                assert set(body) == {'client_id', 'installation_id', 'installation_name'}
                assert body['client_id'] == CLIENT_ID
                self.installation_id = body['installation_id']
                return Reply(WIRE['start_response'], 201)
            if url == PREFIX + '/pairing/status':
                assert kwargs['headers']['Authorization'] == 'Bearer ' + WIRE['start_response']['device_code']
                assert kwargs['json'] == {'client_id': CLIENT_ID, 'user_code': WIRE['start_response']['user_code']}
                if self.on_status:
                    self.on_status()
                body = copy.deepcopy(self.status_payload or PRODUCER['responses']['controller_success_response']['body'])
                if self.status_payload is None:
                    body['installation_id'] = self.installation_id
                return Reply(body, self.status_code)
            pytest.fail('Unexpected outbound URL: ' + url)

    instance = Peer()
    instance.calls = []
    monkeypatch.setattr(auth.requests, 'post', instance.post)
    monkeypatch.setattr(auth, 'WATCHDOG_API_KEY', '')
    return instance


def config(client):
    response = client.get('/api/account-link/config')
    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.headers['Cache-Control'] == 'no-store'
    assert set(response.json) == {'csrf_token'}
    assert len(response.json['csrf_token']) >= 43
    return {'X-CSRF-Token': response.json['csrf_token'], 'Origin': 'http://localhost'}


def start(client, headers):
    response = client.post('/api/account-link/start', json={}, headers=headers)
    assert response.status_code == 200, response.get_data(as_text=True)
    payload = response.json
    assert set(payload) == {'status', 'attempt_id', 'user_code', 'verification_uri', 'expires_in', 'interval'}
    assert payload['status'] == 'pending'
    assert payload['expires_in'] == 300
    assert payload['interval'] == 5
    assert payload['verification_uri'] == WIRE['transport']['verification_uri']
    return payload['attempt_id']


def post(client, action, attempt, headers, **extra):
    return client.post('/api/account-link/' + action, json={'attempt_id': attempt, **extra}, headers=headers)


def clone(client):
    """A new Flask worker with the same real disk directory and signed cookie."""
    app = auth.create_flask_auth_app()
    app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
    other = app.test_client()
    other.set_cookie('fleet_session', client.get_cookie('fleet_session').value)
    return other


def assert_no_secrets(response, client):
    content = response.get_data(as_text=True)
    assert WIRE['start_response']['device_code'] not in content
    assert NEW_KEY not in content
    with client.session_transaction() as session:
        encoded = json.dumps(dict(session))
        assert WIRE['start_response']['device_code'] not in encoded
        assert NEW_KEY not in encoded


def _commit_in_process(data_dir, cookie, headers, attempt, barrier, results):
    """A fresh interpreter cannot accidentally share in-memory attempt state."""
    auth.DATA_DIR = Path(data_dir)
    auth.AUTH_SECRET_KEY = 'test-secret-key-1234'
    auth.WATCHDOG_API_KEY = ''
    app = auth.create_flask_auth_app()
    app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
    client = app.test_client()
    client.set_cookie('fleet_session', cookie)
    barrier.wait(timeout=10)
    response = post(client, 'commit', attempt, headers, confirm=True)
    results.put((response.status_code, response.json))


def _legacy_write_in_process(data_dir, barrier, results):
    auth.DATA_DIR = Path(data_dir)
    auth.WATCHDOG_API_KEY = ''
    barrier.wait(timeout=10)
    results.put(('legacy', auth.save_watchdog_api_key('sk-ipmi-' + 'c' * 48)))


def _crash_after_key_replacement(data_dir, cookie, headers, attempt):
    import cryptolabs_proxy.account_link as pairing
    auth.DATA_DIR = Path(data_dir)
    auth.AUTH_SECRET_KEY = 'test-secret-key-1234'
    auth.WATCHDOG_API_KEY = ''
    original = pairing.atomic_write
    def crash(path, content, mode=0o600):
        original(path, content, mode)
        if path.name == 'watchdog_api_key':
            os._exit(73)
    pairing.atomic_write = crash
    app = auth.create_flask_auth_app()
    app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
    client = app.test_client()
    client.set_cookie('fleet_session', cookie)
    post(client, 'commit', attempt, headers, confirm=True)


@pytest.mark.parametrize('identity', ['anonymous', 'readonly', 'disabled', 'demoted', 'password_reset'])
def test_config_requires_live_admin(client, admin_user, readonly_user, identity, peer):
    """REQ-PAIR-004/005: signed stale roles never confer local authority."""
    if identity != 'anonymous':
        user = readonly_user if identity == 'readonly' else admin_user
        client.post('/auth/login', data=user)
        if identity == 'disabled':
            auth.update_user('admin', enabled=False)
        elif identity == 'demoted':
            auth.update_user('admin', role='readonly')
        elif identity == 'password_reset':
            auth.update_user('admin', require_password_change=True)
    response = client.get('/api/account-link/config')
    assert response.status_code in (401, 403)
    assert peer.calls == []


@pytest.mark.parametrize('action', ['start', 'status', 'commit', 'cancel'])
@pytest.mark.parametrize('bad_header', ['missing_csrf', 'wrong_origin', 'cross_site'])
def test_mutations_require_csrf_and_exact_origin(logged_in_admin, action, bad_header, peer):
    """REQ-PAIR-004: cross-origin requests cannot start or change a link."""
    headers = config(logged_in_admin)
    if bad_header == 'missing_csrf':
        headers.pop('X-CSRF-Token')
    elif bad_header == 'wrong_origin':
        headers['Origin'] = 'https://localhost:443'
    else:
        headers['Sec-Fetch-Site'] = 'cross-site'
    response = post(logged_in_admin, action, 'unknown', headers, confirm=True)
    assert response.status_code == 403
    assert peer.calls == []


@pytest.mark.parametrize('initial_key', ['', NEW_KEY], ids=['first_link', 'same_key'])
def test_outbound_pairing_stages_then_persists_once_across_workers(logged_in_admin, peer, isolate_data_dir, initial_key):
    """REQ-PAIR-001/003/004/005: outbound only, no secret cookie, intentional commit."""
    if initial_key:
        auth.save_watchdog_api_key(initial_key)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    other = clone(logged_in_admin)
    staged = post(other, 'status', attempt, headers)
    assert staged.status_code == 200
    assert staged.json['status'] == 'awaiting_confirmation'
    assert staged.json['account'] == WIRE['success_response']['account']
    assert staged.json['requires_confirmation'] is True
    assert staged.json['can_commit'] is True
    assert auth.get_watchdog_api_key() == initial_key
    assert_no_secrets(staged, other)
    for path in isolate_data_dir.rglob('*'):
        if path.is_file() and WIRE['start_response']['device_code'].encode() in path.read_bytes():
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    unconfirmed = post(other, 'commit', attempt, headers)
    assert unconfirmed.status_code == 400
    assert auth.get_watchdog_api_key() == initial_key
    linked = post(other, 'commit', attempt, headers, confirm=True)
    assert linked.status_code == 200
    assert linked.json['status'] == 'linked'
    assert auth.get_watchdog_api_key() == NEW_KEY
    assert auth.is_watchdog_verified()
    assert_no_secrets(linked, other)
    dashboard = other.get('/auth/watchdog/sso')
    assert dashboard.location == auth.WATCHDOG_URL.rstrip('/') + '/login'
    dashboard_json = other.get('/auth/watchdog/sso-url')
    assert dashboard_json.json['sso_url'] == dashboard.location
    assert_no_secrets(dashboard_json, other)
    callback = other.get('/auth/watchdog/callback?api_key=' + OLD_KEY)
    assert callback.location == '/auth/account-link'
    assert auth.get_watchdog_api_key() == NEW_KEY
    assert auth._pair_store().paired_account() == WIRE['success_response']['account']
    assert post(logged_in_admin, 'commit', attempt, headers, confirm=True).status_code in (400, 409, 410)
    assert post(logged_in_admin, 'status', attempt, headers).status_code in (400, 409, 410)


@pytest.mark.parametrize('outcome', ['denied', 'network', 'expired', 'mismatched_account', 'extra_credential'])
def test_failed_status_preserves_existing_link(logged_in_admin, peer, monkeypatch, outcome):
    """REQ-PAIR-003/004/005: no failed or malformed peer result replaces credentials."""
    auth.save_watchdog_api_key(OLD_KEY)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    payload = copy.deepcopy(WIRE['success_response'])
    payload.update(client_id=CLIENT_ID, installation_id=peer.installation_id, service_intent='watchdog')
    if outcome == 'denied':
        peer.status_payload, peer.status_code = {'error': 'access_denied'}, 400
    elif outcome == 'network':
        def unavailable():
            raise requests.ConnectionError('synthetic unreachable service')
        peer.on_status = unavailable
    elif outcome == 'expired':
        now = auth.time.time()
        monkeypatch.setattr(auth.time, 'time', lambda: now + 301)
    elif outcome == 'mismatched_account':
        payload['account']['id'] = True
        peer.status_payload = payload
    else:
        payload['credential']['litellm_api_key'] = 'SYNTHETIC-UNEXPECTED-SECRET'
        peer.status_payload = payload
    result = post(logged_in_admin, 'status', attempt, headers)
    assert result.status_code in (400, 409, 410, 502, 503)
    assert_no_secrets(result, logged_in_admin)
    assert auth.get_watchdog_api_key() == OLD_KEY
    assert post(logged_in_admin, 'commit', attempt, headers, confirm=True).status_code != 200


@pytest.mark.parametrize('change', ['cancel', 'supersede', 'config_change', 'session_change', 'logout'])
def test_late_peer_result_cannot_restore_invalidated_attempt(logged_in_admin, peer, change):
    """REQ-PAIR-003/004: real durable compare-current-state wins over late HTTPS."""
    auth.save_watchdog_api_key(OLD_KEY)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    other = clone(logged_in_admin)
    def invalidate():
        if change == 'cancel':
            assert post(other, 'cancel', attempt, headers).status_code == 200
        elif change == 'supersede':
            start(other, headers)
        elif change == 'config_change':
            auth.save_watchdog_api_key('sk-ipmi-' + 'b' * 48)
        elif change == 'logout':
            assert other.get('/auth/logout').status_code == 302
        else:
            auth.update_user('admin', enabled=False)
    peer.on_status = invalidate
    response = post(logged_in_admin, 'status', attempt, headers)
    assert response.status_code in (400, 401, 403, 409, 410)
    assert auth.get_watchdog_api_key() != NEW_KEY
    assert post(other, 'commit', attempt, headers, confirm=True).status_code != 200


def test_parallel_workers_claim_only_one_poll_and_cancel_wins(logged_in_admin, peer):
    """REQ-PAIR-003/004: actual filesystem store serializes workers, not fake atomics."""
    auth.save_watchdog_api_key(OLD_KEY)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    first, second = clone(logged_in_admin), clone(logged_in_admin)
    entered, release = threading.Event(), threading.Event()
    def block():
        entered.set()
        assert release.wait(5), 'test failed to release outbound barrier'
    peer.on_status = block
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(post, first, 'status', attempt, headers)
        try:
            assert entered.wait(5)
            competing = post(second, 'status', attempt, headers)
            assert competing.status_code in (200, 409, 429)
            assert len([url for url, _ in peer.calls if url.endswith('/pairing/status')]) == 1
            assert post(second, 'cancel', attempt, headers).status_code == 200
        finally:
            release.set()
        assert future.result().status_code in (400, 409, 410)
    assert auth.get_watchdog_api_key() == OLD_KEY


def test_independent_processes_cannot_commit_same_stage_twice(logged_in_admin, peer, isolate_data_dir):
    """REQ-PAIR-003/004: the real persistent transaction has one process winner."""
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    assert post(logged_in_admin, 'status', attempt, headers).status_code == 200
    context = multiprocessing.get_context('spawn')
    barrier, results = context.Barrier(2), context.Queue()
    args = (str(isolate_data_dir), logged_in_admin.get_cookie('fleet_session').value,
            headers, attempt, barrier, results)
    processes = [context.Process(target=_commit_in_process, args=args) for _ in range(2)]
    for process in processes:
        process.start()
    try:
        outcomes = [results.get(timeout=15) for _ in processes]
        assert sum(status == 200 for status, _ in outcomes) == 1
        assert sorted(status for status, _ in outcomes)[1] in (400, 409, 410)
    finally:
        for process in processes:
            process.join(timeout=5)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
    assert all(process.exitcode == 0 for process in processes)
    assert auth.get_watchdog_api_key() == NEW_KEY


def test_storage_failure_leaves_old_key_intact(logged_in_admin, peer, isolate_data_dir):
    """REQ-PAIR-004: unwritable persistent storage fails closed at commit."""
    auth.save_watchdog_api_key(NEW_KEY)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    assert post(logged_in_admin, 'status', attempt, headers).status_code == 200
    isolate_data_dir.chmod(0o500)
    try:
        response = post(logged_in_admin, 'commit', attempt, headers, confirm=True)
        assert response.status_code == 503
        assert auth.get_watchdog_api_key() == NEW_KEY
    finally:
        isolate_data_dir.chmod(0o700)


def test_writer_failure_after_new_key_write_restores_unlinked_state(logged_in_admin, peer, monkeypatch):
    import cryptolabs_proxy.account_link as pairing
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    assert post(logged_in_admin, 'status', attempt, headers).status_code == 200
    original, failures = pairing.atomic_write, []
    def fail_verified_once(path, content, mode=0o600):
        if path.name == 'watchdog_verified' and not failures:
            failures.append(True)
            raise OSError('synthetic one-shot disk failure after key replacement')
        return original(path, content, mode)
    monkeypatch.setattr(pairing, 'atomic_write', fail_verified_once)
    assert post(logged_in_admin, 'commit', attempt, headers, confirm=True).status_code == 503
    assert failures == [True]
    assert auth.get_watchdog_api_key() == ''
    assert not (auth.DATA_DIR / 'watchdog_api_key').exists()
    assert not auth.is_watchdog_verified()
    assert post(logged_in_admin, 'commit', attempt, headers, confirm=True).status_code == 409


def test_process_crash_after_key_replace_recovers_unlinked_state_without_replay(logged_in_admin, peer, isolate_data_dir):
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    assert post(logged_in_admin, 'status', attempt, headers).status_code == 200
    process = multiprocessing.get_context('spawn').Process(target=_crash_after_key_replacement,
        args=(str(isolate_data_dir), logged_in_admin.get_cookie('fleet_session').value, headers, attempt))
    process.start()
    process.join(timeout=15)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
    assert process.exitcode == 73
    assert (isolate_data_dir / 'watchdog_api_key').read_text() == NEW_KEY
    assert auth.get_watchdog_api_key() == ''
    assert not (isolate_data_dir / 'watchdog_api_key').exists()
    assert not auth.is_watchdog_verified()
    assert post(logged_in_admin, 'commit', attempt, headers, confirm=True).status_code == 409


def test_concurrent_legacy_writer_is_never_overwritten_by_stale_stage(logged_in_admin, peer, isolate_data_dir):
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    assert post(logged_in_admin, 'status', attempt, headers).status_code == 200
    context = multiprocessing.get_context('spawn')
    barrier, results = context.Barrier(2), context.Queue()
    commit = context.Process(target=_commit_in_process, args=(str(isolate_data_dir),
        logged_in_admin.get_cookie('fleet_session').value, headers, attempt, barrier, results))
    legacy = context.Process(target=_legacy_write_in_process, args=(str(isolate_data_dir), barrier, results))
    for process in (commit, legacy):
        process.start()
    try:
        outcomes = [results.get(timeout=15) for _ in (commit, legacy)]
        assert ('legacy', True) in outcomes
        assert [status for status, _ in outcomes if status != 'legacy'][0] in (200, 409)
    finally:
        for process in (commit, legacy):
            process.join(timeout=5)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
    assert all(process.exitcode == 0 for process in (commit, legacy))
    assert auth.get_watchdog_api_key() == 'sk-ipmi-' + 'c' * 48


def test_different_session_cannot_redeem_or_cancel_attempt(logged_in_admin, admin_user, peer):
    """REQ-PAIR-004: same username after a fresh login is a different binding."""
    auth.save_watchdog_api_key(OLD_KEY)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    fresh = auth.create_flask_auth_app().test_client()
    fresh.post('/auth/login', data=admin_user)
    fresh_headers = config(fresh)
    for action in ('status', 'commit', 'cancel'):
        assert post(fresh, action, attempt, fresh_headers, confirm=True).status_code in (400, 403, 409, 410)
    assert len(peer.calls) == 1
    assert auth.get_watchdog_api_key() == OLD_KEY


def test_environment_conflict_blocks_commit_without_reparenting(logged_in_admin, peer, monkeypatch):
    """REQ-PAIR-005/006: Overview env precedence cannot silently diverge from file."""
    monkeypatch.setattr(auth, 'WATCHDOG_API_KEY', OLD_KEY)
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    assert post(logged_in_admin, 'status', attempt, headers).status_code == 200
    result = post(logged_in_admin, 'commit', attempt, headers, confirm=True)
    assert result.status_code == 409
    assert result.json['error'] == 'configuration_conflict'
    assert auth.get_watchdog_api_key() == OLD_KEY
    assert not (auth.DATA_DIR / 'watchdog_api_key').exists()


@pytest.mark.parametrize('field,value', [('api_key', NEW_KEY), ('device_code', 'forged'), ('account', {'id': 999}), ('verification_uri', 'https://attacker.test')])
def test_browser_cannot_supply_credential_identity_or_destination(logged_in_admin, peer, field, value):
    """REQ-PAIR-001/004/005: browser hints cannot become authority."""
    headers = config(logged_in_admin)
    result = logged_in_admin.post('/api/account-link/start', json={field: value}, headers=headers)
    assert result.status_code == 400
    assert peer.calls == []


@pytest.mark.parametrize('source', ['nginx/nginx.conf', 'src/cryptolabs_proxy/templates/nginx.conf.j2'])
def test_pairing_api_is_routed_to_local_auth_only(source, tmp_path):
    """REQ-PAIR-001/004: shipped and generated nginx expose only the frozen API prefix."""
    if source.endswith('.j2'):
        from cryptolabs_proxy.config import generate_nginx_config
        from cryptolabs_proxy.services import DEFAULT_SERVICES
        generate_nginx_config(tmp_path, 'fleet.example.test', services=dict(DEFAULT_SERVICES))
        text = (tmp_path / 'nginx.conf').read_text()
    else:
        text = (Path(__file__).parents[1] / source).read_text()
    assert 'location ^~ /api/account-link/ {' in text
    block = text.split('location ^~ /api/account-link/ {', 1)[1].split('}', 1)[0]
    assert 'proxy_pass http://127.0.0.1:8081;' in block
    assert 'proxy_set_header Host $http_host;' in block
    assert 'X-Fleet-Auth-Role' not in block


def test_link_page_and_unlinked_entry_use_pairing_without_callback_or_key_url(logged_in_admin, peer):
    response = logged_in_admin.get('/auth/account-link')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    assert 'Confirm this account' in response.text
    assert 'redirect_uri=' not in response.text
    assert auth.WATCHDOG_URL.rstrip('/') + '/login' in response.text
    assert_no_secrets(response, logged_in_admin)
    assert logged_in_admin.get('/auth/watchdog/sso').location == '/auth/account-link'
    assert logged_in_admin.get('/auth/watchdog/sso-url').json['sso_url'] == '/auth/account-link'


def test_nondefault_origin_port_is_required_and_preserved(logged_in_admin, peer):
    response = logged_in_admin.get('/api/account-link/config', base_url='https://localhost:8443')
    assert response.status_code == 200
    headers = {'X-CSRF-Token': response.json['csrf_token'], 'Origin': 'https://localhost'}
    assert logged_in_admin.post('/api/account-link/start', json={}, headers=headers,
        base_url='https://localhost:8443').status_code == 403
    headers['Origin'] = 'https://localhost:8443'
    assert logged_in_admin.post('/api/account-link/start', json={}, headers=headers,
        base_url='https://localhost:8443').status_code == 200


@pytest.mark.parametrize('identity', ['anonymous', 'admin'])
@pytest.mark.parametrize('query', ['', '?api_key=' + NEW_KEY + '&user_email=forged@example.test&subscription=active'])
def test_legacy_callback_discards_query_without_any_link_mutation(logged_in_admin, identity, query):
    """REQ-PAIR-004/005: old popups restart; a GET cannot write account authority."""
    auth.save_watchdog_api_key(OLD_KEY)
    before = (auth.DATA_DIR / 'account_link.json').read_bytes()
    caller = logged_in_admin if identity == 'admin' else auth.create_flask_auth_app().test_client()
    response = caller.get('/auth/watchdog/callback' + query)
    assert response.status_code == 302
    assert response.location == '/auth/account-link'
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    assert auth.get_watchdog_api_key() == OLD_KEY
    assert not auth.is_watchdog_verified()
    assert (auth.DATA_DIR / 'account_link.json').read_bytes() == before
    assert NEW_KEY not in response.text
    assert 'forged@example.test' not in response.text


@pytest.mark.parametrize('stage_format', ['current', 'previous_adapter'])
def test_wp_identity_cannot_replace_different_working_watchdog_key(logged_in_admin, peer, stage_format):
    """REQ-PAIR-004/005: WP account recognition never proves hosted permission."""
    auth.save_watchdog_api_key(OLD_KEY)
    auth.set_watchdog_verified()
    headers = config(logged_in_admin)
    attempt = start(logged_in_admin, headers)
    staged = post(logged_in_admin, 'status', attempt, headers)
    assert staged.status_code == 200
    assert staged.json['account'] == WIRE['success_response']['account']
    assert staged.json['service_status'] == 'unknown'
    assert staged.json['can_commit'] is False
    assert staged.json['reason'] == 'service_validation_failed'
    assert logged_in_admin.get('/auth/watchdog/callback?api_key=' + NEW_KEY).location == '/auth/account-link'
    assert auth.get_watchdog_api_key() == OLD_KEY
    if stage_format == 'previous_adapter':
        # An installed upgrade may inherit a stage the previous adapter marked
        # committable. The fresh commit guard must distrust that cached decision.
        store = auth._pair_store()
        with store.locked() as state:
            state['attempt']['can_commit'] = True
            store.save(state)
    assert post(logged_in_admin, 'commit', attempt, headers, confirm=True).status_code == 409
    assert auth.get_watchdog_api_key() == OLD_KEY
    assert auth.is_watchdog_verified()
