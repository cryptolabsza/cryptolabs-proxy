# Fleet Manager proxy work-item trace evidence

This is a thin product mapping to the [shared baseline](../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/traceability-matrix.md).
REQ/TRACE/VER/VAL-FLEETUPDATE-001 labels normalize exact approved source;
implementation and installed customer acceptance are separate.

## Traceability Matrix

| Trace | Requirement | Implementation | Verification | Validation | Acceptance status | Status |
|---|---|---|---|---|---|---|
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/cryptolabs_proxy/auth.py`, `src/cryptolabs_proxy/config.py`, `src/cryptolabs_proxy/release_client.py`, `src/cryptolabs_proxy/release_selection.py`, `src/cryptolabs_proxy/standard_adoption.py`, `src/cryptolabs_proxy/updates.py`, `scripts/health-api.py` | VER-FLEETUPDATE-001: affected existing suites and shared preimplementation RED artifacts | VAL-FLEETUPDATE-001: shared validation-definition.json | Local implementation candidate; installed/native/browser/owner acceptance held | approved |
| TRACE-PAIR-001 | REQ-PAIR-001 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-001 | VAL-PAIR-001 | Source verification only; installed/public/paid acceptance held | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-002 | REQ-PAIR-002 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-002 | VAL-PAIR-002 | Source verification only; installed/public/paid acceptance held | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-003 | REQ-PAIR-003 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-003 | VAL-PAIR-003 | Source verification only; installed/public/paid acceptance held | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-004 | REQ-PAIR-004 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-004 | VAL-PAIR-004 | Source verification only; installed/public/paid acceptance held | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-005 | REQ-PAIR-005 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-005 | VAL-PAIR-005 | Source verification only; installed/public/paid acceptance held | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-006 | REQ-PAIR-006 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-006 | VAL-PAIR-006 | Source verification only; installed/public/paid acceptance held | Owner-approved source authority; reviewed scope |

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

| src/cryptolabs_proxy/account_link.py | REQ-PAIR-003 | TRACE-PAIR-003 | VER-PAIR-003 | file-role | pairing-store |
| src/cryptolabs_proxy/auth.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | file-role | account-pairing-routes |
| nginx/nginx.conf | REQ-PAIR-001 | TRACE-PAIR-001 | VER-PAIR-001 | file-role | pairing-routing |
| src/cryptolabs_proxy/templates/nginx.conf.j2 | REQ-PAIR-001 | TRACE-PAIR-001 | VER-PAIR-001 | file-role | pairing-routing |
| tests/test_account_link.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | verifies | pairing-verification |
| src/cryptolabs_proxy/auth.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-001 | TRACE-PAIR-001 | VER-PAIR-001 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-003 | TRACE-PAIR-003 | VER-PAIR-003 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | entrypoint | trace-anchor-target |

## Formats outside the Python anchor scanner

The retained Fleet hashes below identify pre-integration head `3b1ff8e4a71da0b0392c976c1fe8c5aa5bfbc002`.
Changed artifact hashes and focused evidence are recorded separately below; historical verification does not cover changed bytes.

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

## Account pairing acceptance boundary

The TRACE-PAIR rows identify owner-approved and quality-reviewed source implementation scope only. Verification is in progress. Central MariaDB/cookie/consent, required CI, independent final review and actual installed Fleet/public-service/paid acceptance remain held until their separate evidence exists. These authority labels do not close any requirement or runtime outcome.


## Generated pairing fixture provenance

These are generated raw data copies within the approved verification scope. Inline trace fields would change the canonical producer/specification artifact. The external mapping is the supported generated-file exception, not a claim of inline source coverage. Exact producer bytes are emitted by the actual WordPress handler under synthetic credentials and compared by consumer tests. No API body, assertion or scanner rule changes. Source implementation and installed acceptance remain separately gated.

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Provenance / acceptance |
| --- | --- | --- | --- | --- | --- |
| tests/fixtures/pairing-producer-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 d58a17f90c33e935b4307b5816e462d0445ee984b72e1d03948dfa3cd9d9404d; regenerate and drift-check from wordpress/actual-producer-fixture.json |
| tests/fixtures/pairing-wire-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 8ccd5db5c28c55da4e9118c7f913e45532e3213007b8e98a4af214f4bb20d652; regenerate and drift-check from fixtures/pairing-wire-v1.json |

## Composed candidate format evidence

| Artifact | SHA256 | Trace | Verification evidence |
|---|---|---|---|
| nginx/nginx.conf | 5a6f8bbd6c9121fb0b1a2fd4884205b996f52c332ae2e0ea9b026fc5a748ed7d | TRACE-FLEETUPDATE-001; TRACE-PAIR-001 | proxy-integration/implementation/format-verification.json and affected.log; separate local Unix socket rerun; protected CI and installed/native/browser acceptance held |
| src/cryptolabs_proxy/templates/nginx.conf.j2 | d14273f48d5370f480870068b8bcf1ebb2a84a868979079ff97549ef8fcdd7ed | TRACE-FLEETUPDATE-001; TRACE-PAIR-001 | proxy-integration/implementation/format-verification.json and affected.log; separate local Unix socket rerun; protected CI and installed/native/browser acceptance held |
| docs/release-selection.md | 1fb846663fce84ae693409de61d222ac031fa6dd77e3eec1d27326ecaf2abbd0 | TRACE-FLEETUPDATE-001 | proxy-integration/implementation/format-verification.json and affected.log; separate local Unix socket rerun; protected CI and installed/native/browser acceptance held |
