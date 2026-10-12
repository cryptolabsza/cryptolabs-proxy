"""Private controller exclusion on the updater's existing auth mount.

This module uses only stdlib so its fixed helper can run without auth startup,
network access, the Docker socket, or the source container's environment.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import uuid
from contextlib import contextmanager

MARKER = 'controller-adoption.json'
MAX_MARKER = 4096
GUARD_IDLE_SECONDS = 300
CAPABILITY = {'schema_version': 1, 'api': 'AdoptionEngine.controller_guard',
              'durable_updater_exclusion': True}
FIELDS = {'schema_version', 'kind', 'operation_id', 'source_id', 'source_image',
          'auth_mount_sha256', 'owner'}


class RecoveryError(RuntimeError):
    """Fixed public failure, without private filesystem or Engine details."""


def _hold():
    raise RecoveryError('controller_recovery_required')


def validate_record(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        _hold()
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['kind'] != 'dc-controller-adoption':
        _hold()
    patterns = {'operation_id': r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}',
                'source_id': r'[0-9a-f]{64}',
                'source_image': r'sha256:[0-9a-f]{64}',
                'auth_mount_sha256': r'[0-9a-f]{64}', 'owner': r'[0-9a-f]{64}'}
    for key, pattern in patterns.items():
        if not isinstance(value[key], str) or not re.fullmatch(pattern, value[key]):
            _hold()
    return value


def _private(info, *, directory=False):
    return ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (directory or info.st_nlink == 1))


@contextmanager
def open_directory(directory):
    """Traverse each parent without following links; create only missing dirs."""
    path = Path(directory)
    if not path.is_absolute() or '..' in path.parts:
        _hold()
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not _private(os.fstat(descriptor), directory=True):
            _hold()
        yield descriptor
    except (OSError, ValueError):
        _hold()
    finally:
        os.close(descriptor)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def read_marker(directory_fd):
    try:
        descriptor = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        _hold()
    try:
        info = os.fstat(descriptor)
        if not _private(info) or info.st_size > MAX_MARKER:
            _hold()
        data = os.read(descriptor, MAX_MARKER + 1)
        if len(data) > MAX_MARKER:
            _hold()
        try:
            value = json.loads(data, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError):
            _hold()
        return validate_record(value)
    finally:
        os.close(descriptor)


def require_clear(directory):
    with open_directory(directory) as descriptor:
        if read_marker(descriptor) is not None:
            _hold()


def _write_marker(directory_fd, value):
    validate_record(value)
    temporary = '.' + MARKER + '-' + uuid.uuid4().hex
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, MARKER, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try: os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError: pass


def open_lock(directory_fd, name):
    descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory_fd)
    if not _private(os.fstat(descriptor)):
        os.close(descriptor)
        _hold()
    return descriptor


@contextmanager
def updater_lock(directory, name):
    with open_directory(directory) as directory_fd:
        descriptor = None
        try:
            descriptor = open_lock(directory_fd, name)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError:
            _hold()
        finally:
            if descriptor is not None:
                os.close(descriptor)


def request(path, owner, action, timeout):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(path)
        client.sendall(json.dumps({'owner': owner, 'action': action}).encode() + b'\n')
        response = b''
        while not response.endswith(b'\n'):
            chunk = client.recv(1024)
            if not chunk: _hold()
            response += chunk
            if len(response) > MAX_MARKER: _hold()
    value = json.loads(response)
    if value != {'owner': owner, 'state': 'completed' if action == 'complete' else 'held'}:
        _hold()
    return value


# This fixed client is executed inside the exact guard helper, never the proxy.
CLIENT_COMMAND = """import json,socket,sys
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
 c.settimeout(2); c.connect('/tmp/controller-guard.sock')
 c.sendall(json.dumps({'owner':sys.argv[1],'action':sys.argv[2]}).encode()+b'\\n')
 data=b''
 while not data.endswith(b'\\n'):
  part=c.recv(1024)
  if not part: raise RuntimeError('guard_unavailable')
  data+=part
  if len(data)>4096: raise RuntimeError('guard_unavailable')
 sys.stdout.buffer.write(data)
"""


def helper_main(directory, socket_path, expected, recover, timeout):
    """Hold real locks until removal; durable marker outlives this process."""
    validate_record(expected)
    with open_directory(directory) as directory_fd:
        descriptors = []
        try:
            deadline = time.monotonic() + timeout
            for name in ('dispatch.lock', 'operation.lock'):
                descriptor = open_lock(directory_fd, name)
                descriptors.append((name, descriptor, os.fstat(descriptor)))
                while True:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline: _hold()
                        time.sleep(.02)
            previous = read_marker(directory_fd)
            if previous is not None:
                if not recover or {k: v for k, v in previous.items() if k != 'owner'} != {k: v for k, v in expected.items() if k != 'owner'}:
                    _hold()
            _write_marker(directory_fd, expected)
            completed = False

            def prove():
                # Reopen by no-follow traversal to detect replaced parent/lock
                # inodes. Fixed helper never unlocks its live descriptors.
                with open_directory(directory) as current_fd:
                    if (os.fstat(current_fd).st_dev, os.fstat(current_fd).st_ino) != (os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino):
                        _hold()
                    for name, descriptor, original in descriptors:
                        current = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                        if not _private(current) or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                            _hold()
                        if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (original.st_dev, original.st_ino):
                            _hold()
                    actual = read_marker(current_fd)
                    if actual != (None if completed else expected): _hold()

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(socket_path)
                os.chmod(socket_path, 0o600)
                server.listen(1)
                verified_at = time.monotonic()
                while True:
                    remaining = GUARD_IDLE_SECONDS - (time.monotonic() - verified_at)
                    if remaining <= 0:
                        return  # Release locks; persisted marker stays in place.
                    server.settimeout(min(remaining, .25))
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(min(2, remaining))
                        try:
                            data = b''
                            while not data.endswith(b'\n'):
                                part = connection.recv(1024)
                                if not part: _hold()
                                data += part
                                if len(data) > MAX_MARKER: _hold()
                            command = json.loads(data)
                            if command not in ({'owner': expected['owner'], 'action': 'check'},
                                               {'owner': expected['owner'], 'action': 'complete'}): _hold()
                            prove()
                            if time.monotonic() - verified_at >= GUARD_IDLE_SECONDS:
                                _hold()
                            verified_at = time.monotonic()
                            if command['action'] == 'complete':
                                if not completed:
                                    os.unlink(MARKER, dir_fd=directory_fd)
                                    os.fsync(directory_fd)
                                    completed = True
                                state = 'completed'
                            else:
                                if completed: _hold()
                                state = 'held'
                            response = {'owner': expected['owner'], 'state': state}
                        except (OSError, ValueError, RecoveryError):
                            response = {'state': 'unavailable'}
                        try: connection.sendall(json.dumps(response).encode() + b'\n')
                        except OSError: pass
        finally:
            for _, descriptor, _ in descriptors: os.close(descriptor)
            try: os.unlink(socket_path)
            except FileNotFoundError: pass


if __name__ == '__main__':
    helper_main(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), sys.argv[4] == 'recover', float(sys.argv[5]))
