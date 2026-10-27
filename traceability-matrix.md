# CryptoLabs Proxy traceability

## Traceability Matrix

| Trace | Requirement | Implementation | Verification | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| TRACE-PAIR-001 | REQ-PAIR-001 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-001 | VAL-PAIR-001 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-002 | REQ-PAIR-002 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-002 | VAL-PAIR-002 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-003 | REQ-PAIR-003 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-003 | VAL-PAIR-003 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-004 | REQ-PAIR-004 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-004 | VAL-PAIR-004 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-005 | REQ-PAIR-005 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-005 | VAL-PAIR-005 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-006 | REQ-PAIR-006 | src/cryptolabs_proxy/auth.py; src/cryptolabs_proxy/account_link.py; tests/test_account_link.py; nginx/nginx.conf; src/cryptolabs_proxy/templates/nginx.conf.j2 | VER-PAIR-006 | VAL-PAIR-006 | Owner-approved source authority; reviewed scope |

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

## Generated pairing fixture provenance

These are generated raw data copies within the approved verification scope. Inline trace fields would change the canonical producer/specification artifact. The external mapping is the supported generated-file exception, not a claim of inline source coverage. Exact producer bytes are emitted by the actual WordPress handler under synthetic credentials and compared by consumer tests. No API body, assertion or scanner rule changes. Source implementation and installed acceptance remain separately gated.

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Provenance / acceptance |
| --- | --- | --- | --- | --- | --- |
| tests/fixtures/pairing-producer-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 d58a17f90c33e935b4307b5816e462d0445ee984b72e1d03948dfa3cd9d9404d; regenerate and drift-check from wordpress/actual-producer-fixture.json |
| tests/fixtures/pairing-wire-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 8ccd5db5c28c55da4e9118c7f913e45532e3213007b8e98a4af214f4bb20d652; regenerate and drift-check from fixtures/pairing-wire-v1.json |
