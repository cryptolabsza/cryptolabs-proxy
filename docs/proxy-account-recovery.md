# Proxy account continuity and certificate preflight

The persisted `users.json` store owns customer passwords, roles, enabled state,
lockout state, and password-change requirements. Installer environment values
bootstrap only an absent store. An existing empty, malformed, or unreadable
store fails authentication startup and requires recovery; setup never replaces
it with an installer account. Valid custom users remain authoritative even when
the installer account name is absent.

If standard adoption fails after starting the selected candidate, recovery
restores only the proxy's owned auth files and checks all unrelated shared
files. The old image first runs its actual authentication startup in an isolated
container, with no published ports or network and an empty bootstrap password.
Only after its account state matches can a recreated container serve the
original image, settings, mounts, and network endpoints. The original container
stays stopped. Recovery changes the container identity and clears its obsolete
`FLEET_ADMIN_PASS`; session and internal authority keys remain continuous.
Failed proof, recreation, or serving verification is recorded as requiring
forward repair. Private recovery snapshots contain credentials and must remain
private. A retained original container must not be manually restarted with its
obsolete bootstrap password.

Certificate acquisition never stops the current proxy or host web server.
A compatible running proxy uses its inspected ACME webroot; otherwise certbot
tries a standalone listener and fails safely if port 80 is busy. When a release
selection explicitly requests Let's Encrypt, acquisition failure leaves the
current service and existing proxy certificate files in place and reports the
failure. It does not substitute a self-signed certificate. Selected Nginx
validation retains the exact Let's Encrypt and ACME path mounts used by the
runtime and must pass before setup frees service ports.

Existing running or stopped proxies must use the inspected host adoption route.
Ordinary setup holds before certificate, network, or container changes when an
unadopted proxy already exists; it reserves default stores and topology for an
absent installation. Write a supported declaration after inspecting the
customer's routes, stores, certificate mounts, and selection. With the newly
published host CLI installed, run:

```sh
cryptolabs-proxy configuration inspect
cryptolabs-proxy configuration plan --declaration /root/proxy-declaration.json
cryptolabs-proxy configuration adopt --declaration /root/proxy-declaration.json --plan-id <plan-id>
```

Use the plan ID returned by `plan`; changes invalidate it. An existing empty,
malformed, unreadable, or invalid identity store blocks adoption before stopping
the source. Repair that customer authority explicitly before retrying; adoption
never invents accounts to make an invalid store pass. Recovery restores owned
files and proves the actual old initializer before restoring endpoint topology.
The original stopped container is not reconnected ahead of that proof.

The general updater reports
`proxy_replacement_policy: "host-adoption-required-v1"` through
`cryptolabs_proxy.updates.get_capabilities()` and
`python3 -m cryptolabs_proxy.updates capabilities`. The selection contract and
owner metadata remain unchanged. Proxy replacement requires host adoption
authority; the capability is a prerequisite, not a new lifecycle owner.
Before dispatching any selected helper, including pulls and updates of other
selected services, the host reads that capability from the actual inspected
running source container using Docker exec. It requires an integer selection
contract of 1 and the exact replacement policy above. Missing, malformed,
unknown, or unavailable responses hold before publishing a job or creating its
helper and direct the operator to the published host `configuration plan/adopt`
commands. The installed host getter, an image no-op, and container labels cannot
certify the source-image helper. A verified live source continues to support
immutable selected no-ops, pulls, and updates of other selected services.
The new updater holds a proxy replacement and an entire update bundle that
would include it before any service changes. Read-only pulls, exact same-image
proxy no-ops, and independently requested updates of other services remain
supported.

A running old proxy still dispatches helpers from its own old source image.
Installing a new host package cannot repair those existing helpers or browser
update code. Migrate it with the newly published host `configuration plan/adopt`
commands before customer dogfood; do not use the old browser update to cross
that boundary. A missing or unknown replacement capability requires that same
published host adoption route. The host commands preserve source account state,
session authority, integrations and original-image recovery instead of relying
on version strings, labels, or an empty bootstrap value as a safety certificate.
