# Adopt supported standard proxy configuration

Use the ordinary installed `cryptolabs-proxy` host CLI as root. The serving
proxy stays unchanged during `inspect` and `plan`; neither command creates
files, validators, containers or volumes. SHA256 establishes byte identity,
not publisher trust. The host operator must approve the release-selection
manifest and the published proxy/module provenance through the normal release
workflow before adoption.

```sh
cryptolabs-proxy configuration inspect
cryptolabs-proxy configuration plan --declaration /root/proxy-declaration.json
cryptolabs-proxy configuration adopt --declaration /root/proxy-declaration.json \
  --plan-id EXACT_PLAN_ID_FROM_PLAN
```

The declaration is strict JSON, with no passwords, keys, commands, Nginx
snippets or secret values. Unknown and duplicate fields are rejected. Example:

```json
{
  "schema_version": 1,
  "domain": "fleet.example.test",
  "tls": "self-signed",
  "release_selection_dir": "/etc/dc-overview/releases",
  "services": {
    "dc-overview": {"container_name": "dc-overview", "path": "/dc/", "port": 5001},
    "ipmi-monitor": {"container_name": "ipmi-monitor", "path": "/ipmi/", "port": 5000},
    "grafana": {"container_name": "grafana", "path": "/grafana/", "port": 3000},
    "prometheus": {"container_name": "prometheus", "path": "/prometheus/", "port": 9090},
    "vastai-exporter": {"container_name": "vastai-exporter", "path": "/vastai-metrics/", "port": 8622},
    "runpod-exporter": {"container_name": "runpod-exporter", "path": "/runpod-metrics/", "port": 8623},
    "vast-price-manager": {"container_name": "vast-price-manager", "path": "/vast-pricing/", "port": 8088}
  },
  "obsolete_overlays": [],
  "obsolete_owner_labels": []
}
```

`tls` is `self-signed` (existing `/etc/nginx/ssl/server.crt` and `server.key`,
HTTP and HTTPS) or `letsencrypt` (existing certificate directory at
`/etc/letsencrypt/live/<domain>`, HTTPS with HTTP ACME/redirect). Adoption does
not acquire or replace certificates. Their mounted stores are preserved and
mounted read-only in the isolated `nginx -t` validator. An existing Let's
Encrypt profile must already be represented by supported configuration;
unknown appended virtual hosts or certificate directives block adoption.

Every active route and directive is structurally compared with packaged
supported standard profiles or the read-only bootstrap profile from released
1.2.0 source. Unknown behavior fails closed with a directive/route context.
The legacy bootstrap has all its product routes, so every corresponding
service must be explicitly registered with its existing target/port. A VPM
route also requires VPM registration. Removing a custom marker or omitting
an active service cannot bypass coverage. Sanitized metadata alone does not
prove equivalence: run the ordinary plan against the actual active config.
Unsupported existing behavior requires a supported declarative product field
and release, then a new plan; no arbitrary passthrough is available.

Known product paths are fixed. VPM retains its dedicated admin-only route.
Additional services may declare a safe lowercase name/container, a disjoint
path ending in `/`, an integer port1–65535, and optional plain display_name.
Their generated route strips that prefix, retains the suffix/query and
requires Fleet authentication. Reserved auth/API/assets/exporter paths and
prefix collisions are rejected. Site differences belong in these supported
fields, not copied Nginx text.

Only an obsolete read-only single-file bind at
`/app/src/cryptolabs_proxy/auth.py` can be retired. Its declaration must include
`destination`, exact predecessor `sha256`, `replacement_sha256`, and
`equivalence_evidence_sha256` of the operator-reviewed release evidence.
The evidence hash is an operator attestation/precondition, not an automatic
semantic-equivalence verdict. The replacement module hash must equal the
installed normal package module, and every adoption verifies that the selected
immutable image contains that exact module before any stop. Source drift
blocks. Unknown code mounts or custom executable entrypoints block. Optional
obsolete owner labels must be explicitly named `cryptolabs.migration.*` labels.
Inactive predecessor files and private source/state snapshots remain for
recovery; the serving candidate has no retired overlay bind.

The plan binds the actual source container/config/runtime/registry,
declaration, generated configuration, approved selection/manifest bytes,
platform and immutable selected proxy artifact. Adoption holds the existing
registry lock, pre-pulls the digest, verifies repository digest/platform,
validates the production generated Nginx with preserved certificate mounts,
and rechecks identities before a proxy-only compensated switch. It never
kills ports or restarts Docker or unrelated stacks. Mounts, networks, aliases,
configured static IPs, deployed runtime settings, account store and session key
remain continuous. The approved directory mounts read-only at
`/etc/cryptolabs/releases`; Watchtower remains false.

Run adoption during a controlled maintenance window with writers to
product-owned auth files quiesced. Adoption holds both updater dispatch and
operation locks in the same shared auth store throughout the switch and
recovery. Queued/running jobs or an occupied updater lock block before any
proxy stop. An isolated guard container has only the auth mount, no network or
Docker socket, and never initializes accounts. The source snapshot is checked
once before stopping and again after stopping; intervening store drift restarts
the source without creating a candidate. If an interrupted host process leaves
the guard container behind, inspect the recorded recovery/runtime outcome
before removing that guard or retrying. The original shared auth mount is retained, so DC consumers continue
to see future token/key updates. Recovery restores only product-owned
users/settings/exporter/watchdog files, verifies their hashes before the old
image starts, and never rewrites unknown shared files, internal tokens or job
state. Changes to those external files block old-image restoration and record
`forward_repair_required`. Candidate auth observations are separately retained
privately, including when a candidate schema must be recovered after failed
source health restoration. The outcome records actual observed runtime states;
inspect them before retry. Do not infer an image-only rollback restored data.

After candidate health and anonymous auth boundary proof, supported
services/domain/TLS/selection configuration is persisted and `custom_config`
is removed as completed adoption. A persistence failure retains the proven
candidate and marks required forward repair; it is not a successful adoption.
Public results never claim positive operator login. Verify real login/roles,
account identities, session continuity and state with the operator before
accepting the deployment. The CLI's anonymous probes prove rejection, not
successful authenticated use.

Repeating adoption with its original plan returns `already_adopted` only when
recorded serving identities, declaration, selection and config still match.
Ordinary `cryptolabs-proxy setup` repeats the adopted path without the old
bootstrap wizard; programmatic `setup_proxy` and credential recreation delegate
to the same preserved-runtime reconfiguration. Session/internal signing keys
are retained despite default-generated values in ProxyConfig. Persisted user
records are authoritative: installation environment passwords bootstrap only
an empty account store. Adoption, restart and setup never overwrite a changed
customer password. Use authenticated account management to change credentials.
Normal selected-release setup validates Nginx against its actual certificate
mounts before port cleanup/replacement. Successful host Let's Encrypt setup
mounts `/etc/letsencrypt` read-only and the local ACME webroot at
`/var/www/certbot`, matching its generated certificate/challenge paths. Changed
services or declarative domain/TLS use the supported registry/plan/adopt path
and a fresh identity. Active source/policy drift always requires a fresh plan.
Manual recovery snapshots are private mode0700 directories/mode0600 files;
never publish them or include inspected environment/state contents in logs.

Named external virtual hosts use optional `host_forward_groups`. Each group
requires a disjoint explicit lowercase DNS `hostnames` vector, separate
`http` and `https` origin objects, `certificate` and `certificate_key` paths,
and optional boolean `http2` (default true). Example:

```json
{
  "host_forward_groups": [{
    "hostnames": ["app.example.test", "api.example.test"],
    "http": {"origin": "http://192.0.2.10:80"},
    "https": {
      "origin": "https://192.0.2.10",
      "verify_tls": false,
      "sni": true,
      "forwarded_proto": "https",
      "websocket": true,
      "read_timeout_seconds": 300,
      "send_timeout_seconds": 300,
      "buffering": false,
      "max_body_size_mb": 100
    },
    "certificate": "/etc/nginx/ssl/server.crt",
    "certificate_key": "/etc/nginx/ssl/server.key",
    "http2": true
  }],
  "acme_challenge": {
    "origin": "http://192.0.2.20:8999",
    "connect_timeout_seconds": 2,
    "read_timeout_seconds": 10
  }
}
```

These fields extend the full declaration above; they are not standalone input.
Origins accept only the corresponding HTTP/HTTPS scheme and a DNS name or IP
with optional port1–65535. Credentials, URL paths, queries, fragments, wildcard
hosts, primary-domain collisions and overlapping hostname groups are rejected.
Certificate paths are limited to direct files in `/etc/nginx/ssl` or the normal
Let's Encrypt `live/<name>/fullchain.pem` and `privkey.pem` paths. Adoption
preserves the original certificate mounts; mounted ACME/Let's Encrypt volumes
alone never select the certificate mode.

HTTPS backend verification defaults to `verify_tls: true`, using the system CA
bundle. `ca_certificate` may explicitly select a certificate at a supported
certificate path. Existing unverified upstream TLS requires the explicit
`verify_tls: false` choice shown above. SNI defaults on. Each protocol object
may declare booleans `websocket` and `buffering`, timeouts
`read_timeout_seconds`, `send_timeout_seconds`, `connect_timeout_seconds`
(1–3600), `max_body_size_mb` (1–1024), and `forwarded_proto` (`scheme` or its
own protocol). Unspecified forwarding defaults come from normal Nginx; Host,
client IP and forwarded-protocol headers use the fixed product rules. No
arbitrary headers or directives can be supplied. Paths and query strings reach
the selected backend unchanged. These hosts delegate ordinary authentication
to that backend; the four Fleet VPM session/reauth endpoints return404, and
Fleet authority/exporter management headers are removed before forwarding.

The independent optional `acme_challenge` object serves only the fixed
`^~ /.well-known/acme-challenge/` prefix on the suite server. It allows a safe
HTTP `origin` and bounded connect/read timeouts (defaults2/10 seconds), retains
the URI and Host, and removes Fleet authority headers. It does not acquire
certificates or change `tls`. With self-signed TLS the suite server handles both HTTP and HTTPS. With
Let's Encrypt this proxy applies to the suite HTTPS server; the separate HTTP
challenge server retains its ordinary local challenge store.

Structural adoption comparison covers the complete source, including exact
forward-server ordering, targets, header/WebSocket/timeouts/body/TLS intent
and auth-deny locations. The released bootstrap comparison profile only
substitutes explicitly declared forwarding and ACME values; extra directives,
unknown hosts, reordered behavior or unrepresented targets still block before
any mutation. Successful adoption persists both optional fields. Ordinary
configuration generation and repeat setup retain them through the registry,
without reconstructing or copying old custom Nginx source.
