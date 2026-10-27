# Fleet Manager proxy work-item trace evidence

This is a thin product mapping to the [shared baseline](../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/traceability-matrix.md).
REQ/TRACE/VER/VAL-FLEETUPDATE-001 labels normalize exact approved source;
implementation and installed customer acceptance are separate.

## Traceability Matrix

| Trace | Requirement | Implementation | Verification | Validation | Acceptance status | Status |
|---|---|---|---|---|---|---|
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/cryptolabs_proxy/auth.py`, `src/cryptolabs_proxy/config.py`, `src/cryptolabs_proxy/release_client.py`, `src/cryptolabs_proxy/release_selection.py`, `src/cryptolabs_proxy/standard_adoption.py`, `src/cryptolabs_proxy/updates.py`, `scripts/health-api.py` | VER-FLEETUPDATE-001: affected existing suites and shared preimplementation RED artifacts | VAL-FLEETUPDATE-001: shared validation-definition.json | Local implementation candidate; installed/native/browser/owner acceptance held | approved |

The `approved` authority status above records only the exact owner-approved plan.
Implementation candidate; all installed/runtime/native/browser/requirement closure remains unaccepted and held.

## Code Anchor Evidence

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
| --- | --- | --- | --- | --- | --- |
| src/cryptolabs_proxy/auth.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-implementation |
| src/cryptolabs_proxy/release_client.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-implementation |
| src/cryptolabs_proxy/release_selection.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-implementation |
| src/cryptolabs_proxy/standard_adoption.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-implementation |
| src/cryptolabs_proxy/updates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-implementation |
| scripts/health-api.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-implementation |
| tests/test_auth.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | verification |
| tests/test_updates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | verification |
| tests/test_release_selection.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | verification |
| tests/test_standard_adoption.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | verification |
| src/cryptolabs_proxy/auth.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-entrypoint |
| src/cryptolabs_proxy/release_client.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-entrypoint |
| src/cryptolabs_proxy/release_selection.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-entrypoint |
| src/cryptolabs_proxy/standard_adoption.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-entrypoint |
| src/cryptolabs_proxy/updates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-entrypoint |
| scripts/health-api.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-entrypoint |
| tests/test_proxy_customer_route_repairs.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | verification |
| src/cryptolabs_proxy/standard_adoption.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-recovery |
| src/cryptolabs_proxy/config.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | fleet-release-compose-consumer |
| src/cryptolabs_proxy/config.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | fleet-release-compose-consumer |

## Formats outside the Python anchor scanner

These are manually mapped under the frozen profile; no unsupported-format scanner pass is claimed.

| Artifact | SHA256 | Trace | Verification evidence |
|---|---|---|---|
| landing-page/index.html | 20061e8140c5132b68f0bdc5a7ebfd48023534cf6f1ea7f2921ea6d04530ff37 | TRACE-FLEETUPDATE-001 | proxy-repair-cycle1/format-verification.json + focused-final.log + full-suite.log; native/browser acceptance held |
| nginx/nginx.conf | 7993c9adc7b90f9c79cc569470008a124bb31763ecbc3cf12105cd906c930fbb | TRACE-FLEETUPDATE-001 | proxy-repair-cycle1/format-verification.json + focused-final.log + full-suite.log; native/browser acceptance held |
| src/cryptolabs_proxy/templates/nginx.conf.j2 | 6b40f203f6331d6610e558e7a42655f8917fa87ce8ada5edc6f844ffab274377 | TRACE-FLEETUPDATE-001 | proxy-repair-cycle1/format-verification.json + focused-final.log + full-suite.log; native/browser acceptance held |
| src/cryptolabs_proxy/templates/docker-compose.yml.j2 | ec923fb17e99c649bb0aacd95eb8aeee465cfc9dbc6c65b721461cbf094a8856 | TRACE-FLEETUPDATE-001 | proxy-repair-cycle1/format-verification.json + focused-final.log + full-suite.log; native/browser acceptance held |
| docs/release-selection.md | e7b27805bd35954c3f51cbeab2b28eff936ad3ac90c816e96906a0da8f9ce18e | TRACE-FLEETUPDATE-001 | proxy-repair-cycle1/format-verification.json + focused-final.log + full-suite.log; native/browser acceptance held |

Evidence directory: `../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/proxy-implementation/`.

Immutable prior profile (data bytes preserved; no inserted Python anchor):

| Artifact | SHA256 | Trace | Verification evidence |
|---|---|---|---|
| src/cryptolabs_proxy/templates/previous-standard-nginx-444d7c0.conf.j2 | f12e2b9800cbaa0e49e685506cfaad38eb7e568fa6d239fa15277af59073d8de | TRACE-FLEETUPDATE-001 | proxy-repair-cycle1/previous-standard-provenance.json; exact complete rendered tree and unknown directive rejection in test_standard_adoption.py |
