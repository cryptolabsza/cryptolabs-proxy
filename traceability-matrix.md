# CryptoLabs Proxy traceability

## Traceability Matrix

| Trace | Requirement | Implementation | Verification | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| TRACE-UPGRADEBUTTON-001 | REQ-UPGRADEBUTTON-001 | landing-page/index.html; src/cryptolabs_proxy/updates.py; tests/test_latest_status.py; tests/test_release_selection.py | VER-UPGRADEBUTTON-001 | VAL-UPGRADEBUTTON-001 | Owner-approved source scope |
| TRACE-PAIR-001 | REQ-PAIR-001 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-001 | VAL-PAIR-001 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-002 | REQ-PAIR-002 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-002 | VAL-PAIR-002 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-003 | REQ-PAIR-003 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-003 | VAL-PAIR-003 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-004 | REQ-PAIR-004 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-004 | VAL-PAIR-004 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-005 | REQ-PAIR-005 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-005 | VAL-PAIR-005 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-006 | REQ-PAIR-006 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-006 | VAL-PAIR-006 | Owner-approved source authority; reviewed scope |
| TRACE-UPDATER-001 | REQ-UPDATER-001 | src/cryptolabs_proxy/migration.py; src/cryptolabs_proxy/updates.py; tests/test_updates.py; tests/test_proxy_lifecycle_review_repairs.py | VER-UPDATER-001 | VAL-UPDATER-001 | Owner-approved source implementation scope |
| TRACE-UPDATER-002 | REQ-UPDATER-002 | src/cryptolabs_proxy/migration.py; src/cryptolabs_proxy/updates.py; tests/test_updates.py; tests/test_proxy_lifecycle_review_repairs.py | VER-UPDATER-002 | VAL-UPDATER-002 | Owner-approved source implementation scope |
| TRACE-UPDATER-003 | REQ-UPDATER-003 | src/cryptolabs_proxy/standard_adoption.py; src/cryptolabs_proxy/templates/released-standard-1.5.4/; tests/test_standard_adoption.py | VER-UPDATER-003 | VAL-UPDATER-003 | Owner-approved source implementation scope |

## Account pairing acceptance boundary

The TRACE-PAIR rows identify owner-approved and quality-reviewed source implementation scope only. Verification is in progress. Central MariaDB/cookie/consent, required CI, independent final review and actual installed Fleet/public-service/paid acceptance remain held until their separate evidence exists. These authority labels do not close any requirement or runtime outcome.

## Code Anchor Evidence

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
| --- | --- | --- | --- | --- | --- |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-003 | TRACE-PAIR-003 | VER-PAIR-003 | file-role | pairing-store |
| src/cryptolabs_proxy/auth.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | file-role | account-pairing-routes |
| nginx/nginx.conf | REQ-PAIR-001 | TRACE-PAIR-001 | VER-PAIR-001 | file-role | pairing-routing |
| src/cryptolabs_proxy/templates/nginx.conf.j2 | REQ-PAIR-001 | TRACE-PAIR-001 | VER-PAIR-001 | file-role | pairing-routing |
| tests/test_account_link.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | verifies | pairing-verification |
| src/cryptolabs_proxy/auth.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-001 | TRACE-PAIR-001 | VER-PAIR-001 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-003 | TRACE-PAIR-003 | VER-PAIR-003 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/account_link.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | entrypoint | trace-anchor-target |
| src/cryptolabs_proxy/migration.py | REQ-UPDATER-001 | TRACE-UPDATER-001 | VER-UPDATER-001 | file-role | bounded-docker-stop-transport |
| src/cryptolabs_proxy/migration.py | REQ-UPDATER-001 | TRACE-UPDATER-001 | VER-UPDATER-001 | entrypoint | bounded-docker-stop-transport |
| src/cryptolabs_proxy/updates.py | REQ-UPDATER-002 | TRACE-UPDATER-002 | VER-UPDATER-002 | file-role | safe-update-recovery-diagnostics |
| src/cryptolabs_proxy/updates.py | REQ-UPDATER-002 | TRACE-UPDATER-002 | VER-UPDATER-002 | entrypoint | safe-update-recovery-diagnostics |
| tests/test_updates.py | REQ-UPDATER-002 | TRACE-UPDATER-002 | VER-UPDATER-002 | file-role | persisted-updater-failure-contract |
| tests/test_updates.py | REQ-UPDATER-002 | TRACE-UPDATER-002 | VER-UPDATER-002 | verifies | persisted-updater-failure-contract |
| tests/test_proxy_lifecycle_review_repairs.py | REQ-UPDATER-001 | TRACE-UPDATER-001 | VER-UPDATER-001 | file-role | real-stop-socket-deadline |
| tests/test_proxy_lifecycle_review_repairs.py | REQ-UPDATER-001 | TRACE-UPDATER-001 | VER-UPDATER-001 | verifies | real-stop-socket-deadline |
| src/cryptolabs_proxy/standard_adoption.py | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | file-role | strict-released-standard-source |
| src/cryptolabs_proxy/standard_adoption.py | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | entrypoint | strict-released-standard-source |
| tests/test_standard_adoption.py | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | file-role | historical-adoption-contract |
| tests/test_standard_adoption.py | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | verifies | historical-adoption-contract |
| landing-page/index.html | REQ-UPGRADEBUTTON-001 | TRACE-UPGRADEBUTTON-001 | VER-UPGRADEBUTTON-001 | file-role | selected-service-update-control |
| tests/test_latest_status.py | REQ-UPGRADEBUTTON-001 | TRACE-UPGRADEBUTTON-001 | VER-UPGRADEBUTTON-001 | verifies | selected-service-page-contract |
| tests/test_release_selection.py | REQ-UPGRADEBUTTON-001 | TRACE-UPGRADEBUTTON-001 | VER-UPGRADEBUTTON-001 | verifies | selection-status-contract |

| src/cryptolabs_proxy/templates/released-standard-1.5.4/acme-challenge.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 7e594162700825757c9d402971094448aa1834d1f7121ac1c02f152f345e149a; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/exporter-auth-routes.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 450f4c418c09474ac45b6dd314c47cc090fe7d230a0206b30e48c7975023133b; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/fleet-api-routes.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 6991ca6bf1dd4b258e8ee7851fc69ef50b19dfe2353570e4911a0ebadc68ed1b; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/host-forwarding.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 35c4a1fe1d3001865a77d7653350b7a61968953b94172dc7063bc31a42c0f9f7; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/nginx.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 f12e2b9800cbaa0e49e685506cfaad38eb7e568fa6d239fa15277af59073d8de; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/provenance.json | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 addd4a945cf32982a2a7dac30ad2d1eea8eb32585400b28d74c4e9df57e105e5; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/standard-service-routes.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 ef0f55aae48e35127d288781e68281a371505ba27384c8fd04dff9200dce3963; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/vast-price-manager-auth-blocks.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 b9d7013434557492887b0600bc2afc92227ee17f9efebe55b0cccc4b16bd3f81; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| src/cryptolabs_proxy/templates/released-standard-1.5.4/vast-price-manager.conf.j2 | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 32483d169a09c42653396e66c5c7efe1995bd599f44f11ee64fa2f0731a0a2f8; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| tests/fixtures/released-standard-1.5.4-declaration.json | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 c4f4f3e80ff3920522502f47335120e133bca6d8e8245133d0112b550f382274; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| tests/fixtures/released-standard-1.5.4-provenance.json | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 a3203f4e7ef156b403cd039d53c7dc2f02940499c1abb1c862cd52fa5524bff3; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |
| tests/fixtures/released-standard-1.5.4.nginx.conf | REQ-UPDATER-003 | TRACE-UPDATER-003 | VER-UPDATER-003 | Exception | Immutable released/synthetic resource; SHA256 f1aa7a0ed767e7432dd21123fc0086e0cc98e0b26ad3c95eff5fe233095e3e72; root-precode-review.json generated_resource_anchor_exception; external provenance mapping, no inline mutation |

## Generated pairing fixture provenance

These are generated raw data copies within the approved verification scope. Inline trace fields would change the canonical producer/specification artifact. The external mapping is the supported generated-file exception, not a claim of inline source coverage. Exact producer bytes are emitted by the actual WordPress handler under synthetic credentials and compared by consumer tests. No API body, assertion or scanner rule changes. Source implementation and installed acceptance remain separately gated.

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Provenance / acceptance |
| --- | --- | --- | --- | --- | --- |
| tests/fixtures/pairing-producer-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 d58a17f90c33e935b4307b5816e462d0445ee984b72e1d03948dfa3cd9d9404d; regenerate and drift-check from wordpress/actual-producer-fixture.json |
| tests/fixtures/pairing-wire-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 8ccd5db5c28c55da4e9118c7f913e45532e3213007b8e98a4af214f4bb20d652; regenerate and drift-check from fixtures/pairing-wire-v1.json |


## Updater stop repair — approved scope, outcomes pending

# Scoped updater matrix proposal (not applied to unrelated pairing authority)


| Trace | Requirement | Implementation | Verification | Validation | Status |
| --- | --- | --- | --- | --- | --- |

Updater rows authorize source implementation only. GREEN/review/release checks and operational acceptance remain open until their evidence exists. Compatibility addendum is awaiting owner approval; no deployment GO is asserted.

Selected-service upgrade control runtime acceptance remains pending; definition `.traceweaver/upgrade-button-20261104/validation.md`. Source scope follows the explicit owner request, without a deployed-outcome claim.
