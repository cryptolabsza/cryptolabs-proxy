# TRACEWEAVER: file-role=fleet-release-implementation; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Bounded client for the installed Fleet release owner, with no remote paths."""
import json
import os
from pathlib import Path
import re
import socket
import stat
import uuid

from .release_selection import COMPONENTS

SOCKET_PATH = '/run/dc-overview-release-broker.sock'
MAX_REQUEST = 65536
MAX_RESPONSE = 1048576


class ReleaseBrokerError(ValueError):
    def __init__(self, code, message='Release owner unavailable.', status=503):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


def strict_json(raw):
    if isinstance(raw,bytes): raw=raw.decode('utf-8')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate_field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_number')))


def validate_params(action, params):
    fields = {'list': {'channel'}, 'preview': {'candidate_ids','components','expected_selection_id','expected_selection_sha256','operation_kind'},
              'apply': {'operation_id','preview_id','preview_sha256','expected_selection_id','expected_selection_sha256'},
              'status': {'operation_id'}, 'recover': {'operation_id'}}
    if action not in fields or not isinstance(params, dict) or set(params) != fields[action]:
        raise ReleaseBrokerError('invalid_request', 'Invalid release request fields.', 400)
    for key, value in params.items():
        if key in ('candidate_ids','components'):
            if (not isinstance(value, list) or not 1 <= len(value) <= 32
                    or any(not isinstance(x,str) or not 1 <= len(x) <= 128 for x in value)
                    or len(set(value)) != len(value) or key == 'components' and any(x not in COMPONENTS for x in value)):
                raise ReleaseBrokerError('invalid_request','Invalid release component scope.',400)
        elif not isinstance(value,str) or not 1 <= len(value) <= 128:
            raise ReleaseBrokerError('invalid_request','Invalid release request value.',400)
        elif key.endswith('_sha256') and not re.fullmatch('[0-9a-f]{64}',value):
            raise ReleaseBrokerError('invalid_request','Invalid release digest.',400)
        elif key == 'operation_id':
            try:
                if str(uuid.UUID(value)) != value: raise ValueError()
            except ValueError: raise ReleaseBrokerError('invalid_request','Invalid operation identifier.',400) from None
    if 'channel' in params and params['channel'] not in ('main','dev'):
        raise ReleaseBrokerError('invalid_channel','Use main or dev.',400)
    if 'operation_kind' in params and params['operation_kind'] not in ('services-update','proxy-adopt'):
        raise ReleaseBrokerError('invalid_request','Invalid release operation.',400)
    return params


class ReleaseBrokerClient:
# TRACEWEAVER: entrypoint=request; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
    def request(self, action, params, *, actor):
        validate_params(action,params)
        if (not isinstance(actor,dict) or set(actor) != {'kind','username','subject'}
                or actor.get('kind') != 'fleet-admin' or any(not isinstance(actor[k],str) or not 1<=len(actor[k])<=128 for k in ('username','subject'))):
            raise ReleaseBrokerError('invalid_actor','Release administrator identity required.',403)
        raw=json.dumps({'schema_version':1,'action':action,'params':params,'actor':actor},separators=(',',':'),allow_nan=False).encode()+b'\n'
        if len(raw)>MAX_REQUEST: raise ReleaseBrokerError('request_too_large','Release request too large.',413)
        try:
            metadata=Path(SOCKET_PATH).lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=0 or metadata.st_mode & 0o077:
                raise OSError('unsafe_owner_socket')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(SOCKET_PATH)
                connection.settimeout(15)
                connection.sendall(raw)
                connection.shutdown(socket.SHUT_WR)
                response=bytearray()
                while True:
                    chunk=connection.recv(min(65536,MAX_RESPONSE+1-len(response)))
                    if not chunk: break
                    response.extend(chunk)
                    if len(response)>MAX_RESPONSE: raise ValueError('response_too_large')
                value=strict_json(bytes(response))
            if (not isinstance(value,dict) or type(value.get('schema_version')) is not int or value['schema_version']!=1
                    or type(value.get('ok')) is not bool): raise ValueError('invalid_response')
            if value['ok']:
                if set(value)!={'schema_version','ok','result'} or not isinstance(value['result'],dict): raise ValueError('invalid_response')
                return value['result']
            if set(value)!={'schema_version','ok','error'}: raise ValueError('invalid_response')
            error=value['error']
            if (not isinstance(error,dict) or set(error)!={'code','message','status'}
                    or type(error['status']) is not int or not 400<=error['status']<=599
                    or not isinstance(error['code'],str) or not re.fullmatch('[a-z][a-z0-9_-]{0,79}',error['code'])
                    or not isinstance(error['message'],str) or len(error['message'])>512): raise ValueError('invalid_response')
            raise ReleaseBrokerError(error['code'],error['message'],error['status'])
        except ReleaseBrokerError:
            raise
        except (OSError,ValueError,UnicodeError,TypeError):
            raise ReleaseBrokerError('owner_unavailable','Release owner unavailable; no update confirmed.',503) from None
