# Fleet Manager bounded work-item authority

REQ-FLEETUPDATE-001 is an administrative label for the exact five-step revision 2
Fleet Manager plan approved by the owner on 27 October 2026. It adds no requirement
semantics or approval.

Canonical authority: [owner receipt](../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/owner-approval.json),
[approved plan](../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-plan/plan.json),
and [shared work-item requirements](../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/requirements.md).
Approved plan SHA256: `ec14802b47a1078ad6b1d051ba2943d43c77160e5bfe119c366eb4209caec516`.

Repair truthful version/job status and let a Fleet administrator preview and
update admitted managed components, including Fleet Manager itself through the
installed host adoption owner. First installation remains operator-owned;
routine later updates use the UI or equivalent CLI.

Production trust/admission, bootstrap, packaged Linux and browser acceptance,
retained rollback and final owner acceptance remain held until independently
verified. No feature version bump or publication is part of this worktree change.

# CryptoLabs Proxy scoped requirements


## Main 1.6 stock-profile compatibility evidence

`FLEET-MAIN16-COMPAT-20261102` is a bounded integration repair under the existing
REQ-FLEETUPDATE-001 authority. The owner-approved amendment SHA256 is
`159af8421e4dde61e4ecc4f47849a1ddd7f07cd6fb158d247256f0bb36ed316e`.
The accepted [child plan](../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/main16-compat/plan/plan.json)
and [root source GO](../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/main16-compat/plan/root-source-go.json)
bound this repair to the exact released Main `8e2b421` standard profile. Existing
Fleet and pairing requirement statements remain authoritative. Verification
uses VER-FLEETUPDATE-001 and the [worktree RED and V&V definition](../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/main16-compat/definition/).
Local implementation, package evidence and final independent review do not close
VAL-FLEETUPDATE-001; protected CI, native and installed browser/site acceptance
remain separately held. No recovery or native operation budget is reset.


## Owner-approved account pairing — PAIR-20261028-01

Source: latest owner approval quoted in `.traceweaver/account-pairing-20261028/authority.json`. Reviewed scope hash: `9b80ccd96837cae1dd63723fa10ce8390dc4305fcc9e65f303a4868a917dc922`. The exact shared protocol is `.traceweaver/account-pairing-20261028/contract.json`. Existing requirements remain authoritative; this appendix governs only the approved pairing increment. Delivery and paid-service acceptance remain held until observed.

### REQ-PAIR-001

A deployment administrator shall be able to link IPMI Monitor or the DC Overview/Watchdog controller to an existing or newly created CryptoLabs account using outbound HTTPS to the existing public CryptoLabs WordPress service for account pairing. Existing product service validation may use its existing approved HTTPS endpoint. Provider VPN access, an inbound deployment callback and per-deployment hostname admission shall not be prerequisites.

Verification: `VER-PAIR-001`; validation: `VAL-PAIR-001`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-002

The public linking flow shall require signed-in account consent through a nonce-protected POST for the matching displayed one-time user code. Opening a link, signing up or presenting a payment-success parameter alone shall not authorize a deployment.

Verification: `VER-PAIR-002`; validation: `VAL-PAIR-002`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-003

Pending linking attempts shall expire after 300 seconds, enforce bounded issuance, approval guesses and polling, and permit only one successful redemption through atomic persistent transitions across workers. Secret device codes shall remain backend-only and shall not be stored in plaintext by WordPress.

Verification: `VER-PAIR-003`; validation: `VAL-PAIR-003`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-004

A deployment shall accept a result only for the initiating current local administrator and session. It shall stage and verify the authoritative result before an intentional commit, consume the local attempt once, and preserve an existing working link on failure, denial, cancellation, expiry, session change or account mismatch. A first link may save verified WordPress identity with no paid grant when service validation fails; an existing different working credential/configuration shall not be replaced by a candidate that fails service validation. A same-key re-link shall not newly assert paid readiness on validation failure.

Verification: `VER-PAIR-004`; validation: `VAL-PAIR-004`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-005

The new flow shall deliver only the existing product account credential and allowlisted authoritative identity/status fields over a backend HTTPS response. It shall preserve current service entitlement/quota decisions, worker-scoped credentials and local administration/update authority. Pairing shall not grant a new paid entitlement, change retention/outage policies, or give the provider host access.

Verification: `VER-PAIR-005`; validation: `VAL-PAIR-005`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-006

The implementation shall preserve existing working links and legacy clients, keep the current pinned WordPress package/publisher boundary, and deliver installed product updates through accepted DC Overview Fleet Management. Deployment and paid-service acceptance shall remain held until observed in the intended environment.

Verification: `VER-PAIR-006`; validation: `VAL-PAIR-006`. See scoped authority and protocol for executable acceptance boundaries.


## 2 November 2026 native service recovery amendment

The existing administrative REQ/TRACE/VER/VAL-FLEETUPDATE-001 labels also
project the exact owner-approved [continuation amendment](../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/architecture/continuation-amendment.json),
SHA256 `159af8421e4dde61e4ecc4f47849a1ddd7f07cd6fb158d247256f0bb36ed316e`,
and its [owner receipt](../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/owner-approval.json). The frozen implementation
contract is [contract.json](../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/contract/contract.json), SHA256
`91b873c548da7d10a113c8fbb74f09540559ba51339514c738e081d0dc75cf01`.
This is a linked projection, not a new approval or requirement identity.

The fixed root host command verifies retained pre-job evidence and the exact
original service before publishing a private job-bound `original_restored`
receipt. The failed job and active pointer stay intact. Selector, native submit
and worker revalidate restoration and retain predecessor dependencies through
blocked successors. New-job phase diagnostics contain only allowlisted facts.
Source tests do not establish actual Linux bootstrap, release, target or browser
acceptance; those gates and publication remain held.

## REQ-UPDATER-001 — owner-approved updater repair

Bounded stop-only acknowledgement headroom; preserve existing stop grace (13s default), other socket timeouts and readiness deadlines.

Authority: `.traceweaver/updater-stop-20261104/authority.json`, unchanged approved plan control. Verification: `VER-UPDATER-001`; validation: `VAL-UPDATER-001`. Intended-environment acceptance remains held.


## REQ-UPDATER-002 — owner-approved updater repair

Fixed allowlisted phase/category diagnostics, safe known wrapped-cause classification, separate primary/recovery failure; no exception text/payload/credentials/traceback serialization; diagnostics cannot interrupt recovery. Preserve rollback, identity, selection and native guards.

Authority: `.traceweaver/updater-stop-20261104/authority.json`, unchanged approved plan control. Verification: `VER-UPDATER-002`; validation: `VAL-UPDATER-002`. Intended-environment acceptance remains held.


## REQ-UPDATER-003 — owner-approved historical-profile prerequisite

Recognize one explicitly named released-standard1.5.4 source via complete ordered structural equality and immutable eight-template historical closure; preserve current candidate rendering, auth/module identity, selection/source drift denial, declaration and recovery guards. Verify matching official wheel/container and disposable staging adoption before bounded separate official hostvenv provisioning, fixed native Proxy adoption and the already-approved single LTX IPMI retry.

Authority: `.traceweaver/updater-stop-20261104/compatibility/owner-approval.json` and approved addendum. Verification `VER-UPDATER-003`; validation `VAL-UPDATER-003`. Operational outcomes remain held.

## Owner-approved per-service stable following (4 November2026)

Exact authority: `.traceweaver/auto-advance-20261104/plan.md`, SHA256 `94b783d925834004cd3f111dd2437f8ae531850f0184aaa29c52f89f84267795`; receipt `owner-approval.json`. Administrative REQ/TRACE/VER/VAL-AUTOADVANCE-001 through -008 map one-to-one to approved C1-C8 without changing their meaning. Source and verification may proceed; publication/runtime claims require their own current checks. Existing Fleet dependency holds remain.

### REQ-AUTOADVANCE-001 — approved C1

An authenticated Fleet administrator can switch one supported managed service between Pinned and Follow stable; the visible installed/selected version and mode remain distinct.

### REQ-AUTOADVANCE-002 — approved C2

Removing a pin opts only that service into verified stable candidates. Existing pins remain pinned by default. Pin current version freezes the verified installed digest; if its identity/provenance cannot be established, the operation fails without changing policy.

### REQ-AUTOADVANCE-003 — approved C3

Follow stable selects the newest admitted compatible non-prerelease version within the installed major version. No downgrade; a major upgrade requires explicit selection. No usable newer candidate leaves the current selection intact and reports why.

### REQ-AUTOADVANCE-004 — approved C4

Selection refresh occurs on Check Updates and a daily host-side check, including when no browser is open. It changes only opted-in services. Mode changes and refresh never install or restart containers. The existing Update action handles installation.

### REQ-AUTOADVANCE-005 — approved C5

Policy mutation uses the existing host owner boundary, authenticated administrator/session/CSRF/origin checks, explicit service scope, bounded fields, selection compare-and-swap, and existing lifecycle locks. A native CLI exposes the same choices. Failed persistence, stale requests, active operations, unavailable discovery or failed trust verification preserve prior selections and modes.

### REQ-AUTOADVANCE-006 — approved C6

Use verified published release/admission metadata, fixed trusted repository/channel sources and exact immutable digests. Do not replace digests with mutable :latest tags or loosen publisher/signature checks. External-owned services retain their owning lifecycle workflow; unsupported services show an explanation rather than pretending the change succeeded.

### REQ-AUTOADVANCE-007 — approved C7

Show current mode, installed version, selected target and clear failure/progress states; refreshes cannot silently re-pin or cross major versions. Re-pinning prevents a concurrent scheduled refresh from advancing afterward.

### REQ-AUTOADVANCE-008 — approved C8

TDD, independent correctness/security review, native Linux lifecycle/policy verification and real-browser checks precede release. Existing LTX data/accounts/settings and unrelated pins/runtimes remain preserved.
