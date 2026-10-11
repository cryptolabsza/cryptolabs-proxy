"""Source-derived, sanitized named forwarding groups; no live/site literals."""
from pathlib import Path
from copy import deepcopy
import pytest
from tests.test_standard_adoption import system
from cryptolabs_proxy.config import generate_nginx_config
from cryptolabs_proxy.standard_adoption import StandardAdoption, AdoptionError, _declaration, render_standard

FIXTURE=Path(__file__).parent/'fixtures/forwarding-source.nginx.conf'


def group():
    return {'hostnames':['app'+str(i)+'.example.test' for i in range(1,8)],
        'http':{'origin':'http://192.0.2.10:80'},
        'https':{'origin':'https://192.0.2.10','verify_tls':False,'sni':True,'forwarded_proto':'https','websocket':True,'read_timeout_seconds':300,'send_timeout_seconds':300,'buffering':False,'max_body_size_mb':100},
        'certificate':'/etc/nginx/ssl/server.crt','certificate_key':'/etc/nginx/ssl/server.key','http2':True}


def test_full_sanitized_actual_source_has_exact_supported_coverage(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    settings['host_forward_groups']=[group()]; settings['acme_challenge']={'origin':'http://192.0.2.20:8999','connect_timeout_seconds':2,'read_timeout_seconds':10}; engine.config=FIXTURE.read_bytes()
    assert adoption.plan(settings)['source_profile']=='released-bootstrap-1.2.0'
    assert b'http://192.0.2.10:80' in render_standard(_declaration(settings))
    assert b'https://192.0.2.10;' in render_standard(_declaration(settings))


@pytest.mark.parametrize('change',['unknown','target','host','auth','order'])
def test_forward_source_unknown_behavior_blocks_before_actions(tmp_path,monkeypatch,change):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); settings['host_forward_groups']=[group()]; settings['acme_challenge']={'origin':'http://192.0.2.20:8999','connect_timeout_seconds':2,'read_timeout_seconds':10}; engine.config=FIXTURE.read_bytes()
    if change=='unknown': engine.config=engine.config.replace(b'proxy_ssl_verify off;',b'proxy_ssl_verify off; proxy_ssl_protocols TLSv1.1;')
    if change=='target': engine.config=engine.config.replace(b'http://192.0.2.10:80',b'http://192.0.2.11:80')
    if change=='host': engine.config=engine.config.replace(b'app1.example.test',b'unknown.example.test')
    if change=='auth': engine.config=engine.config.replace(b'return 404;',b'return 200;',1)
    if change=='order': engine.config=engine.config.replace(b'proxy_read_timeout 300s;\n            proxy_send_timeout 300s;',b'proxy_send_timeout 300s;\n            proxy_read_timeout 300s;')
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls==[]


@pytest.mark.parametrize('bad',['credentials','path','query','fragment','protocol','port','wildcard','collision','duplicate','header','ca_path','unknown_field'])
def test_forward_declarations_reject_unsafe_fields(tmp_path,monkeypatch,bad):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); item=group(); settings['host_forward_groups']=[item]; engine.config=FIXTURE.read_bytes()
    if bad in ['credentials','path','query','fragment','protocol','port']:
        item['https']['origin']={'credentials':'https://user:password@example.test','path':'https://example.test/private/','query':'https://example.test?secret=1','fragment':'https://example.test#secret','protocol':'file:///etc/shadow','port':'https://example.test:70000'}[bad]
    if bad=='wildcard': item['hostnames']=['*.example.test']
    if bad=='collision': item['hostnames']=[settings['domain']]
    if bad=='duplicate': settings['host_forward_groups'].append(deepcopy(item))
    if bad=='header': item['https']['forwarded_proto']='https; return 200'
    if bad=='ca_path': item['https']['ca_certificate']='/unsafe/../secrets'
    if bad=='unknown_field': item['command']='execute'
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls==[]


def test_normal_generator_secure_default_and_auth_isolation(tmp_path):
    item=group(); del item['https']['verify_tls']; del item['https']['forwarded_proto']
    generate_nginx_config(tmp_path,'fleet.example.test',False,host_forward_groups=[item])
    text=(tmp_path/'nginx.conf').read_text()
    assert 'proxy_ssl_verify on;' in text and 'proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;' in text
    assert text.count('location = /auth/vast-price-manager/session { return 404; }')==3
    assert 'proxy_set_header X-Mgmt-Token "";' in text
    assert 'proxy_set_header X-Fleet-Auth-Token "";' in text


def test_adoption_and_normal_repeat_preserve_explicit_groups(tmp_path,monkeypatch):
    from cryptolabs_proxy.services import ServiceRegistry
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); settings['host_forward_groups']=[group()]; settings['acme_challenge']={'origin':'http://192.0.2.20:8999','connect_timeout_seconds':2,'read_timeout_seconds':10}; engine.config=FIXTURE.read_bytes()
    plan=adoption.plan(settings); assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    assert ServiceRegistry(directory).config['host_forward_groups']==[group()]
    before=engine.config; assert adoption.repeat_setup()[0]
    assert engine.config==before
    generate_nginx_config(directory,settings['domain'],False,ServiceRegistry(directory).services)
    assert b'https://192.0.2.10' in (directory/'nginx.conf').read_bytes()


def test_acme_proxy_is_explicit_and_persists_independently_of_certificate_mode(tmp_path,monkeypatch):
    from cryptolabs_proxy.services import ServiceRegistry
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    settings['host_forward_groups']=[group()]; settings['acme_challenge']={'origin':'http://192.0.2.20:8999','connect_timeout_seconds':2,'read_timeout_seconds':10}; engine.config=FIXTURE.read_bytes()
    plan=adoption.plan(settings); adoption.adopt(settings,plan['plan_id'])
    generate_nginx_config(directory,settings['domain'],False,ServiceRegistry(directory).services)
    text=(directory/'nginx.conf').read_text()
    assert 'location ^~ /.well-known/acme-challenge/' in text
    assert 'proxy_pass http://192.0.2.20:8999;' in text
    acme=text.split('location ^~ /.well-known/acme-challenge/ {',1)[1].split('}',1)[0]
    assert 'proxy_set_header X-Mgmt-Token "";' in acme and 'proxy_set_header X-Fleet-Auth-Token "";' in acme
    assert '/etc/nginx/ssl/server.crt' in text and 'fullchain.pem' not in text
    assert adoption.repeat_setup()[0]


@pytest.mark.parametrize('acme',[{'origin':'https://example.test'}, {'origin':'http://example.test','commands':'execute'}, {'origin':'http://example.test','read_timeout_seconds':0}, 'snippet'])
def test_acme_unsafe_declaration_denied(tmp_path,monkeypatch,acme):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); settings['acme_challenge']=acme
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls==[]
