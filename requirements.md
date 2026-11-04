# CryptoLabs Proxy scoped requirements


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


## REQ-UPDATER-001 — owner-approved updater repair

Bounded stop-only acknowledgement headroom; preserve existing stop grace (13s default), other socket timeouts and readiness deadlines.

Authority: `.traceweaver/updater-stop-20261104/authority.json`, unchanged approved plan control. Verification: `VER-UPDATER-001`; validation: `VAL-UPDATER-001`. Intended-environment acceptance remains held.


## REQ-UPDATER-002 — owner-approved updater repair

Fixed allowlisted phase/category diagnostics, safe known wrapped-cause classification, separate primary/recovery failure; no exception text/payload/credentials/traceback serialization; diagnostics cannot interrupt recovery. Preserve rollback, identity, selection and native guards.

Authority: `.traceweaver/updater-stop-20261104/authority.json`, unchanged approved plan control. Verification: `VER-UPDATER-002`; validation: `VAL-UPDATER-002`. Intended-environment acceptance remains held.


## REQ-UPDATER-003 — owner-approved historical-profile prerequisite

Recognize one explicitly named released-standard1.5.4 source via complete ordered structural equality and immutable eight-template historical closure; preserve current candidate rendering, auth/module identity, selection/source drift denial, declaration and recovery guards. Verify matching official wheel/container and disposable staging adoption before bounded separate official hostvenv provisioning, fixed native Proxy adoption and the already-approved single LTX IPMI retry.

Authority: `.traceweaver/updater-stop-20261104/compatibility/owner-approval.json` and approved addendum. Verification `VER-UPDATER-003`; validation `VAL-UPDATER-003`. Operational outcomes remain held.


## REQ-UPGRADEBUTTON-001 — requested selected-service upgrade control repair

The owner requests completion through CI, LTX deployment, updated IPMI and a working upgrade button. The bounded repair exposes the existing approved selected-service update action and binds the displayed selection identity, retaining unmanaged pins, external ownership, Proxy host adoption and backend guards. Authority: `.traceweaver/upgrade-button-20261104/authority.json`; verification `VER-UPGRADEBUTTON-001`, validation `VAL-UPGRADEBUTTON-001`. Runtime acceptance remains pending.
