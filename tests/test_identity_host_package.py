"""Account semantics shared by host authority and server startup stay pure."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


def test_identity_validator_imports_with_only_stdlib():
    source=Path(__file__).resolve().parents[1]/'src/cryptolabs_proxy/identity.py'
    code=f"import sys,importlib.util;spec=importlib.util.spec_from_file_location('identity',{str(source)!r});module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.validate_identity_users({{'custom':{{'password_hash':'hash','role':'readonly','enabled':True,'require_password_change':True}}}});assert 'cryptolabs_proxy.auth' not in sys.modules"
    result=subprocess.run([sys.executable,'-I','-S','-c',code],capture_output=True,text=True)
    assert result.returncode==0,result.stderr


def test_server_auth_exports_same_pure_validator():
    from cryptolabs_proxy import auth,identity
    assert auth.validate_identity_users is identity.validate_identity_users
    assert auth.VALID_ROLES is identity.VALID_ROLES


@pytest.mark.parametrize('users',[{},[],None,{'name':{}},{'name':{'password_hash':'hash','role':'anonymous'}},{'name':{'password_hash':'hash','role':'admin','enabled':1}},{'name':{'password_hash':'hash','role':'admin','require_password_change':'true'}}])
def test_pure_validator_rejects_invalid_identity_without_mutating(users):
    from cryptolabs_proxy.identity import validate_identity_users
    before=json.dumps(users)
    with pytest.raises(ValueError):validate_identity_users(users)
    assert json.dumps(users)==before


def test_pure_validator_preserves_custom_user_without_admin_and_unknown_fields():
    from cryptolabs_proxy.identity import validate_identity_users
    users={'custom':{'password_hash':'hash','role':'readonly','unknown':{'customer':'preserved'}}}
    before=json.dumps(users)
    assert validate_identity_users(users) is None
    assert json.dumps(users)==before
