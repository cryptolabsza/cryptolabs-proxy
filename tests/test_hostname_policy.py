"""Closed policy from observed guards; synthetic full trees are not site proof."""
from copy import deepcopy
from pathlib import Path
import json
import pytest

from cryptolabs_proxy.config import generate_nginx_config
from cryptolabs_proxy.services import ServiceRegistry
from cryptolabs_proxy.standard_adoption import AdoptionError, _declaration, parse_nginx, render_standard
from tests.test_standard_adoption import system
from tests.test_host_forwarding import group

POLICY = 'primary-only'
GUARD = b'if ($host != fleet.example.test) {\n            return 444;\n        }'


def primary_servers(data):
    http = next(children for words, children in parse_nginx(data) if words == ['http'])
    return [children for words, children in http if words == ['server'] and
            any(w == ['server_name', 'fleet.example.test'] for w, c in children)]


@pytest.mark.parametrize('tls', [False, True])
def test_policy_guards_both_primary_listeners_before_acme(tmp_path, tls):
    generate_nginx_config(tmp_path, 'fleet.example.test', tls, hostname_policy=POLICY)
    servers = primary_servers((tmp_path/'nginx.conf').read_bytes())
    assert len(servers) == (2 if tls else 1)
    for server in servers:
        guard = next(
            i for i, (w, c) in enumerate(server) if w == ['if', '($host', '!=', 'fleet.example.test)'] and c == [[['return', '444'], None]])
        for i, (words, _) in enumerate(server):
            if words[0] == 'listen': assert 'default_server' in words
            if words[0] == 'location': assert guard < i


def test_omitted_policy_retains_original_generated_bytes(tmp_path):
    generate_nginx_config(tmp_path, 'fleet.example.test')
    baseline = (tmp_path/'nginx.conf').read_bytes()
    generate_nginx_config(tmp_path, 'fleet.example.test', hostname_policy=None)
    assert (tmp_path/'nginx.conf').read_bytes() == baseline
    assert b'return 444;' not in baseline


@pytest.mark.parametrize('policy', ['allow-all', 'primary-only; return 200', {}, {'scope':'primary'}, True, 444, []])
def test_closed_policy_rejected_before_output(tmp_path, policy):
    from cryptolabs_proxy.setup import ProxyConfig
    with pytest.raises(ValueError): generate_nginx_config(tmp_path, 'fleet.example.test', hostname_policy=policy)
    with pytest.raises(ValueError): ProxyConfig('fleet.example.test', hostname_policy=policy)
    assert not (tmp_path/'nginx.conf').exists()


@pytest.mark.parametrize('domain', ['127.0.0.1', '_', '$host', '*.example.test', 'fleet.example.test)', 'fleet..test', 'fleet.example.test.', 'FLEET.example.test', '-fleet.example.test', 'a'*64+'.test'])
def test_policy_requires_literal_primary_domain_before_effects(tmp_path, domain):
    from cryptolabs_proxy.setup import ProxyConfig
    with pytest.raises(ValueError): generate_nginx_config(tmp_path, domain, hostname_policy=POLICY)
    with pytest.raises(ValueError): ProxyConfig(domain, hostname_policy=POLICY)
    assert not (tmp_path/'nginx.conf').exists()


def test_observed_guard_fixture_is_partial_independent_evidence():
    fixture = json.loads((Path(__file__).parent/'fixtures/hostname-guards-observed.json').read_text())
    assert fixture['source_sha256'] == 'd09306e3c83e203287a2237943f814e8f0748049924f50c339f71db54720628c'
    assert fixture['complete_source'] is False
    assert [(s['guard_index'], s['condition'], s['branch']) for s in fixture['servers']] == [
        (2, ['$host', '!=', 'fleet.example.test'], ['return', 444]),
        (3, ['$host', '!=', 'fleet.example.test'], ['return', 444])]


def test_policy_schema_roundtrip_regeneration_repeat_and_update(tmp_path, monkeypatch):
    from cryptolabs_proxy.setup import ProxyConfig
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings['hostname_policy'] = POLICY
    # This is explicitly synthetic generated standard source, not captured LTX.
    engine.config = render_standard(_declaration(settings))
    plan = adoption.plan(settings)
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'already_adopted'
    registry = ServiceRegistry(directory)
    assert registry.config['hostname_policy'] == POLICY
    assert registry.config['standard_adoption']['declaration']['hostname_policy'] == POLICY
    before = engine.config
    assert adoption.repeat_setup()[0]
    assert engine.config == before
    generate_nginx_config(directory, settings['domain'], services=registry.services)
    assert (directory/'nginx.conf').read_bytes() == before
    assert adoption.reconfigure(ProxyConfig(settings['domain'], use_letsencrypt=False, site_name=''))[0]
    assert engine.config == before
    current = ServiceRegistry(directory).config['standard_adoption']
    assert current['declaration']['hostname_policy'] == POLICY
    assert adoption.repeat_setup()[0]


@pytest.mark.parametrize('change', ['condition', 'variable', 'action', 'extra', 'missing-http', 'missing-https', 'unknown-if', 'route', 'auth', 'tls', 'acme-order', 'acme-route'])
def test_full_standard_tree_counterexamples_fail_before_effects(tmp_path, monkeypatch, change):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, tls='letsencrypt')
    engine.config = render_standard(_declaration(settings))
    assert adoption.plan(settings)['source_profile'] == 'standard'
    if change == 'condition': engine.config = engine.config.replace(b'!= fleet.example.test', b'= fleet.example.test', 1)
    if change == 'variable': engine.config = engine.config.replace(b'($host !=', b'($http_host !=', 1)
    if change == 'action': engine.config = engine.config.replace(b'return 444;', b'return 403;', 1)
    if change == 'extra': engine.config = engine.config.replace(b'return 444;', b'return 444; set $extra 1;', 1)
    if change == 'missing-http': engine.config = engine.config.replace(GUARD, b'', 1)
    if change == 'missing-https':
        prefix, suffix = engine.config.split(b'listen 443', 1); engine.config = prefix+b'listen 443'+suffix.replace(GUARD, b'', 1)
    if change == 'unknown-if': engine.config = engine.config.replace(b'return 444;', b'return 444;', 1)+b'\nif ($host = other.example.test) { return 444; }\n'
    if change == 'route': engine.config = engine.config.replace(b'location /assets/', b'location /lost-assets/', 1)
    if change == 'auth': engine.config = engine.config.replace(b'auth_request /_auth_check;', b'auth_request /_different;', 1)
    if change == 'tls': engine.config = engine.config.replace(b'ssl_protocols TLSv1.2 TLSv1.3;', b'ssl_protocols TLSv1.1;', 1)
    if change == 'acme-order': engine.config = engine.config.replace(GUARD+b'\n', b'', 1).replace(b'location / {\n            return 301', GUARD+b'\n        location / {\n            return 301', 1)
    if change == 'acme-route': engine.config = engine.config.replace(b'location /.well-known/acme-challenge/', b'location /.well-known/unknown/', 1)
    before = {p.name:p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls == []
    assert before == {p.name:p.read_bytes() for p in directory.iterdir()}


def test_primary_policy_does_not_guard_named_forwarding_servers(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, host_forward_groups=[group()])
    engine.config = render_standard(_declaration(settings))
    assert adoption.plan(settings)['source_profile'] == 'standard'
    assert engine.config.count(b'return 444;') == 1
    assert b'server_name app1.example.test' in engine.config
    assert b'proxy_pass http://192.0.2.10:80;' in engine.config


def test_partial_guard_evidence_never_accepts_arbitrary_full_source(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings['hostname_policy'] = POLICY
    engine.config = b'http { server { listen 80 default_server; server_name fleet.example.test; '+GUARD+b' } }'
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls == []


def test_invalid_recorded_policy_blocks_setup_before_inspection(tmp_path, monkeypatch):
    import cryptolabs_proxy.setup as setup
    registry = ServiceRegistry(tmp_path); registry.config.update(domain='fleet.example.test', hostname_policy={'directive':'unsafe'}); registry.save()
    monkeypatch.setattr(setup, 'CONFIG_DIR', tmp_path)
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('no external effects')))
    assert setup.setup_proxy(setup.ProxyConfig('fleet.example.test'))[0] is False


def test_update_auth_reconstruction_retains_policy(tmp_path, monkeypatch):
    import cryptolabs_proxy.setup as setup
    registry = ServiceRegistry(tmp_path); registry.config.update(domain='fleet.example.test', hostname_policy=POLICY, release_selection_dir='/synthetic/releases'); registry.save()
    monkeypatch.setattr(setup, 'CONFIG_DIR', tmp_path)
    monkeypatch.setattr(setup, 'is_proxy_running', lambda: True)
    monkeypatch.setattr(setup, 'get_proxy_config', lambda: {'AUTH_SECRET_KEY':'synthetic'})
    received=[]
    monkeypatch.setattr(setup, 'setup_proxy', lambda config: (received.append(config) or (True, 'preserved')))
    assert setup.update_proxy_credentials('admin', 'synthetic-password', 'synthetic-key')[0]
    assert received[0].hostname_policy == POLICY


def test_independently_captured_full_primary_guard_source(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, http_policy='redirect-primary-https')
    engine.config = (Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    assert adoption.plan(settings)['source_profile'] == 'released-bootstrap-primary-only'
    candidate = render_standard(_declaration(settings))
    assert len(primary_servers(candidate)) == 2
    assert b'return 308 https://fleet.example.test$request_uri;' in candidate
    assert b'location ^~ /.well-known/acme-challenge/' in candidate
    assert b'default_type text/plain;' in candidate
    assert b'try_files $uri =404;' in candidate
    assert b'/etc/nginx/ssl/server.crt' in candidate


@pytest.mark.parametrize('change', ['http-guard', 'https-guard', 'condition', 'variable', 'status', 'extra-branch', 'acme-order', 'acme-body', 'redirect', 'redirect-target', 'auth', 'route', 'tls', 'unknown-if'])
def test_captured_full_tree_mutations_fail_before_effects(tmp_path, monkeypatch, change):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, http_policy='redirect-primary-https')
    engine.config = (Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    assert adoption.plan(settings)['source_profile'] == 'released-bootstrap-primary-only'
    captured_guard = b'if ($host != fleet.example.test) { return 444; }'
    if change == 'http-guard': engine.config = engine.config.replace(captured_guard, b'', 1)
    if change == 'https-guard':
        head, tail = engine.config.split(b'listen 443', 1); engine.config = head+b'listen 443'+tail.replace(captured_guard, b'', 1)
    if change == 'condition': engine.config = engine.config.replace(b'!= fleet.example.test', b'!= other.example.test', 1)
    if change == 'variable': engine.config = engine.config.replace(b'($host !=', b'($http_host !=', 1)
    if change == 'status': engine.config = engine.config.replace(b'return 444;', b'return 403;', 1)
    if change == 'extra-branch': engine.config = engine.config.replace(b'return 444;', b'return 444; set $extra 1;', 1)
    if change == 'acme-order': engine.config = engine.config.replace(captured_guard, b'', 1).replace(b'location / {\n            return 308', captured_guard+b'\n        location / {\n            return 308', 1)
    if change == 'acme-body': engine.config = engine.config.replace(b'try_files $uri =404;', b'try_files $uri =200;', 1)
    if change == 'redirect': engine.config = engine.config.replace(b'return 308', b'return 301', 1)
    if change == 'redirect-target': engine.config = engine.config.replace(b'https://fleet.example.test$request_uri', b'https://$host$request_uri', 1)
    if change == 'auth': engine.config = engine.config.replace(b'proxy_pass http://auth_server/auth/headers;', b'proxy_pass http://auth_server/auth/other;', 1)
    if change == 'route': engine.config = engine.config.replace(b'location /assets/', b'location /unknown-assets/', 1)
    if change == 'tls': engine.config = engine.config.replace(b'ssl_certificate /etc/nginx/ssl/server.crt;', b'ssl_certificate /etc/nginx/ssl/other.crt;', 1)
    if change == 'unknown-if': engine.config += b'\nif ($host = unknown.example.test) { return 444; }\n'
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls == []


def test_observed_self_signed_guard_profile_preserves_http_redirect_acme(tmp_path):
    generate_nginx_config(tmp_path, 'fleet.example.test', hostname_policy=POLICY, http_policy='redirect-primary-https')
    data = (tmp_path/'nginx.conf').read_bytes()
    assert len(primary_servers(data)) == 2
    assert b'return 308 https://fleet.example.test$request_uri;' in data
    assert b'try_files $uri =404;' in data


def test_hostname_policy_without_selected_setup_holds_before_external_effects(tmp_path, monkeypatch):
    import cryptolabs_proxy.setup as setup
    monkeypatch.setattr(setup, 'CONFIG_DIR', tmp_path)
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('no external effects')))
    assert not setup.setup_proxy(setup.ProxyConfig('fleet.example.test', hostname_policy=POLICY))[0]


def test_http_policy_persists_independently_through_adoption_and_generators(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, http_policy='redirect-primary-https')
    engine.config = (Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    plan = adoption.plan(settings)
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    registry = ServiceRegistry(directory)
    assert registry.config['http_policy'] == 'redirect-primary-https'
    before = engine.config
    assert adoption.repeat_setup()[0]
    generate_nginx_config(directory, settings['domain'], services=registry.services)
    assert (directory/'nginx.conf').read_bytes() == before
    assert b'proxy_hide_header X-Mgmt-Token;' in before
    assert b'proxy_cookie_flags fleet_session secure httponly samesite=lax;' in before
    assert b'location = /auth/headers { return 404; }' in before


@pytest.mark.parametrize('policy', [True, {}, [], 'redirect', 'return 301'])
def test_closed_http_policy_rejected_before_effects(tmp_path, policy):
    from cryptolabs_proxy.setup import ProxyConfig
    with pytest.raises(ValueError): generate_nginx_config(tmp_path, 'fleet.example.test', http_policy=policy)
    with pytest.raises(ValueError): ProxyConfig('fleet.example.test', http_policy=policy)
    assert not (tmp_path/'nginx.conf').exists()


def test_http_policy_is_independent_of_hostname_admission(tmp_path):
    generate_nginx_config(tmp_path, 'fleet.example.test', http_policy='redirect-primary-https')
    data = (tmp_path/'nginx.conf').read_bytes()
    assert b'return 444;' not in data
    assert b'default_server' not in data
    assert b'return 308 https://fleet.example.test$request_uri;' in data


def test_local_acme_policy_rejects_conflicting_upstream_before_output(tmp_path):
    with pytest.raises(ValueError):
        generate_nginx_config(tmp_path, 'fleet.example.test', http_policy='redirect-primary-https', acme_challenge={'origin':'http://192.0.2.1:8999'})
    assert not (tmp_path/'nginx.conf').exists()


@pytest.mark.parametrize('change', ['cookie', 'header', 'exporter-auth', 'https-primary', 'http-listener', 'unknown-server'])
def test_complete_source_additional_controls_fail_before_effects(tmp_path, monkeypatch, change):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, http_policy='redirect-primary-https')
    engine.config = (Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    assert adoption.plan(settings)['source_profile'] == 'released-bootstrap-primary-only'
    if change == 'cookie': engine.config = engine.config.replace(b'proxy_cookie_flags fleet_session secure httponly samesite=lax;', b'proxy_cookie_flags fleet_session httponly;', 1)
    if change == 'header': engine.config = engine.config.replace(b'proxy_hide_header X-Mgmt-Token;', b'', 1)
    if change == 'exporter-auth': engine.config = engine.config.replace(b'auth_request /_exporter_admin;', b'auth_request /_auth_check;', 1)
    if change == 'https-primary':
        head, tail = engine.config.split(b'listen 443', 1); engine.config = head+b'listen 443'+tail.replace(b'server_name fleet.example.test;', b'server_name _;', 1)
    if change == 'http-listener': engine.config = engine.config.replace(b'listen 80 default_server;', b'listen 80;', 1)
    if change == 'unknown-server': engine.config += b'http { server { listen 8080; return 200; } }'
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls == []


def test_policy_owned_health_probe_uses_primary_host_sni_and_internal_health(tmp_path, monkeypatch):
    from cryptolabs_proxy.config import render_policy_healthcheck
    from cryptolabs_proxy.standard_adoption import AdoptionEngine
    command = render_policy_healthcheck('fleet.example.test', POLICY, 'redirect-primary-https')
    assert '--resolve fleet.example.test:443:127.0.0.1' in command
    assert 'https://fleet.example.test/api/health' in command
    assert 'http://127.0.0.1:8080/api/health' in command
    commands=[]
    from types import SimpleNamespace
    monkeypatch.setattr('subprocess.run', lambda cmd, **kw: commands.append(cmd) or SimpleNamespace(returncode=0), raising=False)
    assert AdoptionEngine().anonymous_auth('proxy', 'self-signed', 'fleet.example.test')
    probe = commands[0][-1]
    compile(probe, '<declared-domain-probe>', 'exec')
    assert 'server_hostname' in probe and 'fleet.example.test' in probe
    assert 'create_default_context' in probe and '_create_unverified_context' not in probe
    assert 'load_verify_locations' in probe and 'create_default_context()' in probe
    assert "status==401" in probe and "status==404" in probe and '8081' in probe


def test_custom_healthcheck_blocks_policy_adoption_before_effects(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, http_policy='redirect-primary-https')
    engine.config = (Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    engine.current['Config']['Healthcheck'] = {'Test':['CMD', 'customer-health-script'], 'Interval':1000000}
    with pytest.raises(AdoptionError, match='healthcheck'): adoption.plan(settings)
    assert engine.calls == []


def test_default_healthcheck_is_policy_owned_in_plan_and_request(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    settings.update(hostname_policy=POLICY, http_policy='redirect-primary-https')
    engine.config = (Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    engine.current['Config']['Healthcheck'] = {'Test':['CMD-SHELL','curl -f http://localhost/api/health && curl -f http://localhost:8080/api/health || exit 1'], 'Interval':30000000000, 'Timeout':10000000000, 'StartPeriod':10000000000, 'Retries':3}
    plan = adoption.plan(settings)
    assert plan['healthcheck_sha256']
    assert plan['healthcheck_action']=='generated-policy-probe'
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    check = engine.request['Config']['Healthcheck']
    assert check['Interval'] == 30000000000 and check['Retries'] == 3
    assert '--resolve fleet.example.test:443:127.0.0.1' in check['Test'][1]


def test_compose_persists_local_acme_and_policy_health(tmp_path):
    from cryptolabs_proxy.config import generate_docker_compose
    import yaml
    registry=ServiceRegistry(tmp_path); registry.config.update(domain='fleet.example.test', http_policy='redirect-primary-https', hostname_policy=POLICY); registry.save()
    generate_docker_compose(tmp_path, 'fleet.example.test', False)
    proxy=yaml.safe_load((tmp_path/'docker-compose.yml').read_text())['services']['cryptolabs-proxy']
    assert './certbot/www:/var/www/certbot:ro' in proxy['volumes']
    assert './certbot/conf:/etc/letsencrypt:ro' not in proxy['volumes']
    assert '--resolve fleet.example.test:443:127.0.0.1' in proxy['healthcheck']['test'][1]


def test_fresh_selected_setup_binds_local_acme_and_installs_policy_health(tmp_path, monkeypatch):
    import cryptolabs_proxy.setup as setup
    from tests.test_proxy_lifecycle_review_repairs import baseline_setup, mounts
    original = setup.ProxyConfig
    monkeypatch.setattr(setup, 'ProxyConfig', lambda *a, **kw: original(*a, **kw, hostname_policy=POLICY, http_policy='redirect-primary-https'))
    result, calls, freed, directory = baseline_setup(tmp_path, monkeypatch, letsencrypt=False)
    assert result[0]
    validation = next(c for c in calls if c[:3] == ['docker','run','--rm'])
    started = next(c for c in calls if c[:3] == ['docker','run','-d'] and '--name' in c and c[c.index('--name')+1] == 'cryptolabs-proxy')
    acme = str(directory/'certbot'/'www')+':/var/www/certbot:ro'
    assert acme in mounts(validation) and acme in mounts(started)
    assert '/etc/letsencrypt:/etc/letsencrypt:ro' not in mounts(started)
    assert '--resolve fleet.example.test:443:127.0.0.1' in started[started.index('--health-cmd')+1]
    registry=ServiceRegistry(directory)
    assert registry.config['http_policy'] == 'redirect-primary-https'
    assert registry.config['hostname_policy'] == POLICY


def test_compose_reload_uses_recorded_domain_when_no_explicit_domain(tmp_path):
    from cryptolabs_proxy.config import generate_docker_compose
    registry=ServiceRegistry(tmp_path); registry.config.update(domain='fleet.example.test', hostname_policy=POLICY); registry.save()
    generate_docker_compose(tmp_path)
    assert 'https://fleet.example.test/api/health' in (tmp_path/'docker-compose.yml').read_text()


def test_copied_certificate_policy_retains_observed_tls_cipher_contract(tmp_path):
    generate_nginx_config(tmp_path, 'fleet.example.test', http_policy='redirect-primary-https')
    text=(tmp_path/'nginx.conf').read_text()
    assert 'ssl_certificate /etc/nginx/ssl/server.crt;' in text
    assert 'ssl_ciphers HIGH:!aNULL:!MD5;' in text
    assert '/etc/letsencrypt/live/' not in text


def test_exact_observed_trusted_health_is_kept_through_adoption_compose_and_repeat(tmp_path, monkeypatch):
    from cryptolabs_proxy.config import generate_docker_compose
    import yaml
    fixture=json.loads((Path(__file__).parent/'fixtures/hostname-health-observed.json').read_text())
    assert fixture['same_as_source_image'] is False
    assert fixture['source_healthcheck_sha256'] == '22e2ce00eceb003f10cad04ac7fc17ea09dfb7ac8eaef6d7a6ceb2e8d9427f3e'
    command=' '.join(fixture['typed_probe']['tokens'])
    adoption, engine, settings, directory=system(tmp_path,monkeypatch)
    settings.update(hostname_policy=POLICY,http_policy='redirect-primary-https')
    engine.config=(Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    current={'Test':['CMD-SHELL',command], 'Interval':60000000000,'Timeout':5000000000,'StartPeriod':10000000000,'Retries':3}
    engine.current['Config']['Healthcheck']=deepcopy(current)
    plan=adoption.plan(settings)
    assert plan['healthcheck_action']=='preserved-verified-source'
    assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    assert engine.request['Config']['Healthcheck']==current
    registry=ServiceRegistry(directory)
    assert registry.config['standard_adoption']['healthcheck']==current
    generate_docker_compose(directory,settings['domain'],False,release_selection_dir=settings['release_selection_dir'],platform='linux/amd64')
    health=yaml.safe_load((directory/'docker-compose.yml').read_text())['services']['cryptolabs-proxy']['healthcheck']
    assert health['test']==current['Test'] and health['interval']=='60000000000ns'
    assert health['timeout']=='5000000000ns' and health['start_period']=='10000000000ns'
    assert '-k' not in health['test'][1]
    assert adoption.repeat_setup()[0]
    assert engine.request['Config']['Healthcheck']==current


@pytest.mark.parametrize('change', ['resolve', 'host', 'scheme', 'route', 'flag', 'shell', 'metadata'])
def test_observed_trusted_health_mutation_still_holds(tmp_path,monkeypatch,change):
    fixture=json.loads((Path(__file__).parent/'fixtures/hostname-health-observed.json').read_text())
    command=' '.join(fixture['typed_probe']['tokens'])
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    settings.update(hostname_policy=POLICY,http_policy='redirect-primary-https')
    engine.config=(Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    if change=='resolve': command=command.replace(':443:127.0.0.1',':443:192.0.2.1')
    if change=='host': command=command.replace('fleet.example.test','unknown.example.test')
    if change=='scheme': command=command.replace('https://','http://')
    if change=='route': command=command.replace('/api/health','/unknown')
    if change=='flag': command=command.replace('-fsS','-fsSk',1)
    if change=='shell': command+='; customer-script'
    engine.current['Config']['Healthcheck']={'Test':['CMD-SHELL',command]}
    if change=='metadata': engine.current['Config']['Healthcheck']['Retries']=True
    with pytest.raises(AdoptionError,match='healthcheck'):adoption.plan(settings)
    assert engine.calls==[]


def test_fresh_policy_probe_verifies_stored_certificate_and_hostname():
    from cryptolabs_proxy.config import render_policy_healthcheck
    command=render_policy_healthcheck('fleet.example.test', POLICY)
    assert '--cacert /etc/nginx/ssl/server.crt' in command
    assert '-k' not in command


@pytest.mark.parametrize('entrypoint', ['policy', 'plan'])
@pytest.mark.parametrize('original,replacement', [
    ('&&', "'&&'"), ('&&', '"&&"'), ('&&', r'\&\&'),
    ('||', "'||'"), ('||', '"||"'), ('||', r'\|\|'),
    ('>/dev/null', "'>/dev/null'"), ('>/dev/null', '">/dev/null"'),
    ('>/dev/null', r'\>/dev/null'),
    (' &&', '\n&&'),
])
def test_health_shell_control_words_must_be_unquoted_operators(tmp_path,monkeypatch,original,replacement,entrypoint):
    from cryptolabs_proxy.config import policy_healthcheck
    fixture=json.loads((Path(__file__).parent/'fixtures/hostname-health-observed.json').read_text())
    command=' '.join(fixture['typed_probe']['tokens']).replace(original,replacement,1)
    current={'Test':['CMD-SHELL',command],'Interval':60000000000,'Timeout':5000000000,'StartPeriod':10000000000,'Retries':3}
    if entrypoint=='policy':
        with pytest.raises(ValueError,match='healthcheck'):
            policy_healthcheck(current,'fleet.example.test',POLICY,'redirect-primary-https')
        return
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    settings.update(hostname_policy=POLICY,http_policy='redirect-primary-https')
    engine.config=(Path(__file__).parent/'fixtures/hostname-source.nginx.conf').read_bytes()
    engine.current['Config']['Healthcheck']=current
    before={p.name:p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(AdoptionError,match='healthcheck'):adoption.plan(settings)
    assert engine.calls==[]
    assert before=={p.name:p.read_bytes() for p in directory.iterdir()}


def test_trusted_health_benign_spacing_keeps_raw_command_and_timings():
    from cryptolabs_proxy.config import policy_healthcheck
    fixture=json.loads((Path(__file__).parent/'fixtures/hostname-health-observed.json').read_text())
    command=' \t '.join(fixture['typed_probe']['tokens'])
    current={'Test':['CMD-SHELL',command],'Interval':60000000000,'Timeout':5000000000,'StartPeriod':10000000000,'Retries':3}
    assert policy_healthcheck(current,'fleet.example.test',POLICY,'redirect-primary-https')==current


@pytest.mark.parametrize('fields', [('hostname_policy',), ('http_policy',), ('hostname_policy','http_policy')])
def test_explicit_null_policies_are_canonical_omissions_after_adoption(tmp_path,monkeypatch,fields):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    engine.current['Config']['Env'].append('FLEET_ADMIN_USER=admin')
    settings.update({name:None for name in fields})
    normalized=_declaration(settings)
    assert not any(name in normalized for name in fields)
    engine.config=render_standard(normalized)
    plan=adoption.plan(settings)
    assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    registry=ServiceRegistry(directory)
    assert not any(name in registry.config['standard_adoption']['declaration'] for name in fields)
    assert not any(name in registry.config for name in fields)
    assert adoption.repeat_setup()[0]


@pytest.mark.parametrize('drift', ['runtime-command','runtime-metadata','recorded-metadata','recorded-missing'])
def test_policy_repeat_setup_rejects_unmapped_health_before_current_fastpath(tmp_path,monkeypatch,drift):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    engine.current['Config']['Env'].append('FLEET_ADMIN_USER=admin')
    settings.update(hostname_policy=POLICY,http_policy='redirect-primary-https')
    engine.config=render_standard(_declaration(settings))
    plan=adoption.plan(settings)
    assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    assert adoption.repeat_setup()[0]
    runtime=engine.containers['cryptolabs-proxy']['Config']['Healthcheck']
    if drift=='runtime-command': runtime['Test']=['CMD-SHELL','curl -k https://127.0.0.1/api/health']
    if drift=='runtime-metadata': runtime['Retries']=True
    if drift.startswith('recorded'):
        registry=ServiceRegistry(directory)
        if drift=='recorded-metadata': registry.config['standard_adoption']['healthcheck']['Retries']=True
        else: registry.config['standard_adoption'].pop('healthcheck')
        registry.save()
    before=len(engine.calls)
    assert not adoption.repeat_setup()[0]
    if drift.startswith('runtime'):
        with pytest.raises(AdoptionError,match='healthcheck'):adoption.plan(settings)
    assert len(engine.calls)==before


def test_enabled_policy_survives_null_other_field_normalization(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    settings.update(hostname_policy=POLICY,http_policy=None)
    normalized=_declaration(settings)
    assert normalized['hostname_policy']==POLICY
    assert 'http_policy' not in normalized


def test_no_policy_repeat_preserves_unowned_health_behavior(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    engine.current['Config']['Env'].append('FLEET_ADMIN_USER=admin')
    plan=adoption.plan(settings)
    assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    engine.containers['cryptolabs-proxy']['Config']['Healthcheck']={'Test':['CMD','customer-health-script']}
    before=len(engine.calls)
    assert adoption.repeat_setup()[0]
    assert len(engine.calls)==before
