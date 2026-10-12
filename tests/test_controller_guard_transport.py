"""Engine-bound exec transport; real client/helper, synthetic HTTP boundary."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from cryptolabs_proxy import migration
from cryptolabs_proxy.standard_adoption import AdoptionEngine, AdoptionError
from tests.test_controller_recovery_guard import LocalEngine, marker, recovery_module

REAL_RUN = subprocess.run


def frame(stream, data):
    return bytes([stream, 0, 0, 0]) + len(data).to_bytes(4, 'big') + data


class EngineTransport(LocalEngine):
    def __init__(self, tmp_path, monkeypatch, failure=None):
        super().__init__(tmp_path)
        self.socket_path = '/private/tmp/declared-engine-A.sock'
        self.failure = failure
        self.execs = {}
        self.transport_calls = []
        self.read_limits = []
        self._controller_guard_rpc = AdoptionEngine._controller_guard_rpc.__get__(self)
        monkeypatch.setenv('DOCKER_HOST', 'tcp://forbidden-engine-B:2375')
        monkeypatch.setenv('DOCKER_CONTEXT', 'forbidden-engine-B')
        monkeypatch.setattr(subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(AssertionError('ambient CLI forbidden')))
        owner = self

        class Connection:
            def __init__(self, socket_path, timeout):
                assert socket_path == owner.socket_path
                assert timeout <= owner.timeout
                self.path = None
            def request(self, method, path, body=None, headers=None):
                owner.transport_calls.append((method, path, owner.socket_path))
                assert method == 'POST'
                self.path = path
                assert json.loads(body) == {'Detach': False, 'Tty': False}
            def getresponse(self):
                exec_id = self.path.split('/')[2]
                body = owner.execute(exec_id)
                class Response:
                    status = 200
                    def read(self, limit):
                        owner.read_limits.append(limit)
                        return body[:limit]
                return Response()
            def close(self): pass
        monkeypatch.setattr(migration, '_UnixHTTPConnection', Connection)

    def _request(self, method, path, payload=None, allowed=(200, 201, 204)):
        self.transport_calls.append((method, path, self.socket_path))
        if method == 'POST' and path.startswith('/containers/') and path.endswith('/exec'):
            helper_id = path.split('/')[2]
            assert helper_id in self.ids.values()
            assert payload['AttachStdout'] is True and payload['AttachStderr'] is True
            assert payload['AttachStdin'] is False and payload['Tty'] is False
            assert payload['Cmd'][:2] == ['python3', '-c']
            exec_id = hashlib.sha256(str(len(self.execs)).encode()).hexdigest()
            self.execs[exec_id] = {'helper_id': helper_id, 'command': payload['Cmd'], 'exit': None}
            return json.dumps({'Id': exec_id}).encode()
        assert method == 'GET' and path.startswith('/exec/') and path.endswith('/json')
        exec_id = path.split('/')[2]
        entry = self.execs[exec_id]
        value = {'ID': exec_id, 'ContainerID': entry['helper_id'], 'Running': False,
                 'ExitCode': entry['exit'], 'ProcessConfig': {'entrypoint': 'python3',
                 'arguments': entry['command'][1:], 'tty': False}}
        if self.failure == 'exit': value['ExitCode'] = 1
        elif self.failure == 'running': value['Running'] = True
        elif self.failure == 'container': value['ContainerID'] = 'wrong-helper'
        elif self.failure == 'exec-id': value['ID'] = 'wrong-exec'
        elif self.failure == 'command': value['ProcessConfig']['arguments'] = ['wrong-client']
        return json.dumps(value).encode()

    def execute(self, exec_id):
        entry = self.execs[exec_id]
        name = next(n for n, value in self.ids.items() if value == entry['helper_id'])
        command = entry['command']
        result = REAL_RUN([sys.executable, '-c', command[2].replace('/tmp/controller-guard.sock', self.socket_paths[name]),
                          *command[3:]], capture_output=True, timeout=2)
        entry['exit'] = result.returncode
        output = result.stdout
        if self.failure == 'owner': output = json.dumps({'owner': '0' * 64, 'state': 'held'}).encode()
        elif self.failure == 'huge': output = b'x' * 20000
        elif self.failure == 'stderr': return frame(2, b'private stderr detail') + frame(1, output)
        elif self.failure == 'short-header': return b'\x01\x00'
        elif self.failure == 'short-body': return frame(1, output)[:-2]
        elif self.failure == 'reserved': return b'\x01\x01\x00\x00' + len(output).to_bytes(4, 'big') + output
        elif self.failure == 'stream': return frame(0, output)
        # Multiple stdout frames must be correctly reassembled.
        middle = len(output) // 2
        return frame(1, output[:middle]) + frame(1, output[middle:])


def test_explicit_engine_transport_ignores_ambient_cli_context_and_recovers(tmp_path, monkeypatch):
    engine = EngineTransport(tmp_path, monkeypatch)
    with engine.controller_guard(engine.source, engine.source['Image'], 'engine-parity') as check:
        check()
        assert marker(engine).exists()
        owner = json.loads(marker(engine).read_text())['owner']
        with pytest.raises(recovery_module().RecoveryError):
            recovery_module().request(next(iter(engine.socket_paths.values())), '0' * 64, 'complete', .3)
        assert json.loads(marker(engine).read_text())['owner'] == owner
    assert marker(engine).exists()
    with engine.controller_guard(engine.source, engine.source['Image'], 'engine-parity', recover=True) as check:
        check.complete()
    assert not marker(engine).exists()
    assert engine.transport_calls and engine.read_limits
    assert all(call[2] == engine.socket_path for call in engine.transport_calls)
    assert all(0 < limit <= 16385 for limit in engine.read_limits)


@pytest.mark.parametrize('failure', ['exit', 'running', 'container', 'exec-id', 'command', 'owner',
                                    'huge', 'stderr', 'short-header', 'short-body', 'reserved', 'stream'])
def test_exec_identity_protocol_and_output_fail_closed(tmp_path, monkeypatch, failure):
    engine = EngineTransport(tmp_path, monkeypatch, failure=failure)
    with pytest.raises(AdoptionError, match='controller_guard_unavailable'):
        with engine.controller_guard(engine.source, engine.source['Image'], 'fail-closed'): pass
    assert marker(engine).exists()
    assert not any(process.poll() is None for process in engine.processes.values())
