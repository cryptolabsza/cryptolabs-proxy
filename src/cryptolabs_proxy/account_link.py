# TRACEWEAVER: file-role=pairing-store; req=REQ-PAIR-003; trace=TRACE-PAIR-003; ver=VER-PAIR-003
"""Outbound account pairing with a bounded, process-serialized local store.

Secrets live in AUTH_DATA_DIR, never in the Flask signed session. Existing
Watchdog's shared key file remains the controller compatibility boundary.
"""

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
import uuid

import requests


ORIGIN = 'https://www.cryptolabs.co.za'
PREFIX = ORIGIN + '/wp-json/cryptolabs/v1'
VERIFICATION_URI = ORIGIN + '/?clai_pair=1'
CLIENT_ID = 'cryptolabs-dc-controller'
TTL = 300


class PairingError(Exception):
    def __init__(self, error, status=409):
        self.error, self.status = error, status


def atomic_write(path, content, mode=0o600):
    """Replace one file durably; a failed writer leaves its old file intact."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class PairStore:
    def __init__(self, directory, environment_key=''):
        self.directory = Path(directory)
        self.environment_key = environment_key
        self.path = self.directory / 'account_link.json'

    @contextmanager
    def locked(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.directory / 'account_link.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if self.path.exists():
                state = json.loads(self.path.read_text())
            else:
                state = {'version': 1, 'generation': 0, 'installation_id': str(uuid.uuid4()),
                         'attempt': None, 'active': None, 'journal': None}
            self.recover(state)
            yield state
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def save(self, state):
        atomic_write(self.path, json.dumps(state, separators=(',', ':')).encode())

    def key(self):
        path = self.directory / 'watchdog_api_key'
        return path.read_text().strip() if path.exists() else self.environment_key

    def fingerprint(self):
        value = [self.key(), self.environment_key,
                 (self.directory / 'watchdog_verified').exists()]
        return hashlib.sha256(json.dumps(value).encode()).hexdigest()

    def recover(self, state):
        """Rollback interrupted multi-file commit before cooperating readers run.

        The persistent attempt was consumed before the first credential write.
        A crash can lose a confirmation, never make its stage redeemable twice.
        External non-cooperating readers still see atomic old/new key files.
        """
        journal = state.get('journal')
        if not journal:
            return
        for name in ('watchdog_api_key', 'watchdog_verified'):
            path = self.directory / name
            snapshot = journal[name]
            if snapshot is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, base64.b64decode(snapshot), 0o644)
        state['active'] = journal['active']
        state['journal'] = None
        self.save(state)

    def bound(self, state, attempt_id, owner, binding):
        attempt = state.get('attempt')
        if not attempt or attempt['id'] != attempt_id:
            raise PairingError('invalid_attempt')
        if attempt['owner'] != owner or not secrets.compare_digest(attempt['binding'], binding):
            raise PairingError('invalid_attempt', 403)
        if attempt['expires_at'] <= time.time():
            state['attempt'] = None
            self.save(state)
            raise PairingError('expired_token', 410)
        if attempt['fingerprint'] != self.fingerprint():
            state['attempt'] = None
            self.save(state)
            raise PairingError('configuration_changed')
        return attempt

    def invalidate(self, binding):
        with self.locked() as state:
            attempt = state.get('attempt')
            if attempt and attempt['binding'] == binding:
                state['attempt'] = None
                state['generation'] += 1
                self.save(state)

# TRACEWEAVER: entrypoint=start; req=REQ-PAIR-001; trace=TRACE-PAIR-001; ver=VER-PAIR-001
    def start(self, owner, binding, live_admin):
        with self.locked() as state:
            state['generation'] += 1
            attempt = {'id': secrets.token_urlsafe(32), 'owner': owner, 'binding': binding,
                       'generation': state['generation'], 'fingerprint': self.fingerprint(),
                       'expires_at': time.time() + TTL, 'state': 'starting'}
            state['attempt'] = attempt
            installation_id = state['installation_id']
            self.save(state)
        try:
            response = exchange('/pairing/start', {'client_id': CLIENT_ID,
                'installation_id': installation_id, 'installation_name': 'DC Overview controller'})
            body = bounded_json(response)
            if (response.status_code != 201 or set(body) != {'protocol_version', 'device_code', 'user_code',
                    'verification_uri', 'expires_in', 'interval'} or body['protocol_version'] != 1
                    or not isinstance(body['device_code'], str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]{43}', body['device_code'])
                    or not isinstance(body['user_code'], str)
                    or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{2}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}', body['user_code'])
                    or body['verification_uri'] != VERIFICATION_URI or type(body['expires_in']) is not int
                    or not 0 < body['expires_in'] <= TTL or type(body['interval']) is not int or body['interval'] != 5):
                raise PairingError('invalid_pairing_response', 502)
            with self.locked() as state:
                current = self.bound(state, attempt['id'], owner, binding)
                if not live_admin():
                    state['attempt'] = None
                    self.save(state)
                    raise PairingError('admin_session_changed', 403)
                current.update(state='pending', device_code=body['device_code'], user_code=body['user_code'],
                    interval=body['interval'], next_poll=0,
                    expires_at=min(current['expires_at'], time.time() + body['expires_in']))
                self.save(state)
            return {'status': 'pending', 'attempt_id': attempt['id'], 'user_code': body['user_code'],
                    'verification_uri': VERIFICATION_URI, 'expires_in': body['expires_in'], 'interval': body['interval']}
        except (requests.RequestException, ValueError, TypeError, KeyError):
            self.invalidate(binding)
            raise PairingError('temporarily_unavailable', 503) from None

# TRACEWEAVER: entrypoint=status; req=REQ-PAIR-003; trace=TRACE-PAIR-003; ver=VER-PAIR-003
    def status(self, attempt_id, owner, binding, live_admin):
        with self.locked() as state:
            attempt = self.bound(state, attempt_id, owner, binding)
            if attempt['state'] == 'staged':
                return public_stage(attempt)
            if attempt['state'] == 'polling' or attempt.get('next_poll', 0) > time.time():
                return {'status': 'pending', 'interval': attempt.get('interval', 5)}
            if attempt['state'] != 'pending':
                raise PairingError('invalid_attempt')
            ticket = secrets.token_urlsafe(24)
            attempt.update(state='polling', ticket=ticket, next_poll=time.time() + attempt['interval'])
            self.save(state)
            device_code, user_code = attempt['device_code'], attempt['user_code']
            installation_id = state['installation_id']
        try:
            reply = exchange('/pairing/status', {'client_id': CLIENT_ID, 'user_code': user_code}, device_code)
            body = bounded_json(reply)
            if reply.status_code == 200:
                account, key = validate_result(body, installation_id)
            elif body.get('error') in ('authorization_pending', 'slow_down'):
                account, key = None, None
            else:
                raise PairingError(body.get('error') if body.get('error') in
                    ('access_denied', 'expired_token', 'invalid_grant') else 'temporarily_unavailable',
                    400 if reply.status_code == 400 else 503)
        except (requests.RequestException, ValueError, TypeError, KeyError):
            with self.locked() as state:
                current = self.bound(state, attempt_id, owner, binding)
                current['state'] = 'pending'
                self.save(state)
            raise PairingError('temporarily_unavailable', 503) from None
        except PairingError:
            self.invalidate(binding)
            raise
        with self.locked() as state:
            current = self.bound(state, attempt_id, owner, binding)
            if current.get('ticket') != ticket:
                raise PairingError('invalid_attempt')
            if not live_admin():
                state['attempt'] = None
                self.save(state)
                raise PairingError('admin_session_changed', 403)
            if account is None:
                interval = body.get('interval', current['interval'] + 5)
                current.update(state='pending', interval=min(60, max(5, interval)) if type(interval) is int else 10)
                current['next_poll'] = time.time() + current['interval']
                self.save(state)
                return {'status': 'pending', 'interval': current['interval']}
            current.pop('device_code', None)
            # WordPress proves identity, not hosted Watchdog permission. Until
            # that existing permission can be checked without enrollment or
            # mutation, only first-link and same-key confirmation may commit.
            current.update(state='staged', account=account, key=key, service_status='unknown',
                can_commit=not self.key() or self.key() == key)
            self.save(state)
            return public_stage(current)

    def cancel(self, attempt_id, owner, binding):
        with self.locked() as state:
            self.bound(state, attempt_id, owner, binding)
            state['attempt'] = None
            self.save(state)
        return {'status': 'cancelled'}

# TRACEWEAVER: entrypoint=commit; req=REQ-PAIR-004; trace=TRACE-PAIR-004; ver=VER-PAIR-004
    def commit(self, attempt_id, owner, binding, live_admin):
        with self.locked() as state:
            attempt = self.bound(state, attempt_id, owner, binding)
            if not live_admin():
                state['attempt'] = None
                self.save(state)
                raise PairingError('admin_session_changed', 403)
            if attempt['state'] != 'staged':
                raise PairingError('confirmation_not_ready')
            if self.environment_key and self.environment_key != attempt['key']:
                raise PairingError('configuration_conflict')
            # Re-evaluate even for a stage persisted by an older adapter.
            if not attempt['can_commit'] or (self.key() and self.key() != attempt['key']):
                raise PairingError('service_validation_failed')
            result = {'status': 'linked', 'account': attempt['account'], 'service_status': attempt['service_status']}
            key = attempt['key']
            snapshots = {}
            for name in ('watchdog_api_key', 'watchdog_verified'):
                path = self.directory / name
                snapshots[name] = base64.b64encode(path.read_bytes()).decode() if path.exists() else None
            snapshots['active'] = state.get('active')
            state.update(attempt=None, journal=snapshots)
            self.save(state)  # One-use consume precedes any visible credential write.
            try:
                atomic_write(self.directory / 'watchdog_api_key', key.encode(), 0o644)
                atomic_write(self.directory / 'watchdog_verified', b'1', 0o644)
                state['active'] = {'account': result['account'], 'key_digest': hashlib.sha256(key.encode()).hexdigest()}
                state['journal'] = None
                self.save(state)
            except OSError:
                state['journal'] = snapshots
                self.recover(state)
                raise
        return result

    def paired_account(self):
        with self.locked() as state:
            active = state.get('active')
            if active and active['key_digest'] == hashlib.sha256(self.key().encode()).hexdigest():
                return active['account']
        return None


def exchange(path, body, bearer=None):
    headers = {'Accept': 'application/json'}
    if bearer:
        headers['Authorization'] = 'Bearer ' + bearer
    return requests.post(PREFIX + path, json=body, headers=headers, timeout=(3.05, 10),
                         verify=True, allow_redirects=False)


def bounded_json(reply):
    if len(reply.content) > 2048:
        raise ValueError('oversize response')
    body = reply.json()
    if not isinstance(body, dict):
        raise ValueError('invalid response')
    return body


def validate_result(body, installation_id):
    if (set(body) != {'protocol_version', 'status', 'client_id', 'installation_id', 'account',
            'credential', 'service_intent', 'authorization'} or type(body['protocol_version']) is not int
            or body['protocol_version'] != 1 or body['status'] != 'complete'
            or body['client_id'] != CLIENT_ID or body['installation_id'] != installation_id
            or body['service_intent'] != 'watchdog' or body['authorization'] != 'existing_service_validation_required'):
        raise ValueError('invalid identity envelope')
    account, credential = body['account'], body['credential']
    if (not isinstance(account, dict) or set(account) != {'id', 'email', 'display_name'}
            or type(account['id']) is not int or account['id'] <= 0
            or not isinstance(account['email'], str) or len(account['email']) > 254
            or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', account['email'])
            or not isinstance(account['display_name'], str) or len(account['display_name']) > 200
            or not isinstance(credential, dict) or set(credential) != {'type', 'api_key', 'scope'}
            or credential['type'] != 'legacy_ipmi_api_key' or credential['scope'] != 'account_wide'
            or not isinstance(credential['api_key'], str)
            or not re.fullmatch(r'sk-ipmi-[A-Za-z0-9_-]{1,256}', credential['api_key'])):
        raise ValueError('invalid account credential')
    return account, credential['api_key']


def public_stage(attempt):
    result = {'status': 'awaiting_confirmation', 'account': attempt['account'],
              'service_status': attempt['service_status'], 'requires_confirmation': True,
              'can_commit': attempt['can_commit']}
    if not attempt['can_commit']:
        result['reason'] = 'service_validation_failed'
    return result
