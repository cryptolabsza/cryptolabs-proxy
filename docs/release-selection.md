# Approved release selection (contract 1)

For a current compatible proxy, host root imports the suite manifest using DC
Overview's normal release-selection workflow. For an existing old unselected
proxy, provision the reviewed declarative release files first as described below,
then use the published host plan/adopt commands before DC import.
SHA256 proves byte identity; it does not establish publisher trust. This proxy
consumer cannot upload/import arbitrary policy through its HTTP API.

Declare `release_selection_dir` as `/etc/dc-overview/releases` in the complete
host configuration declaration, then use the ordinary shipped setup/adoption flow. The directory contains `selection.json` and
`manifests/<sha256>.json`, binds read-only at `/etc/cryptolabs/releases`, and must
remain under host-root custody. Mount the directory so atomic selection-file
replacement remains visible. Setup selects the exact proxy OCI digest and
permanently disables Watchtower for it. DC setup owns labels for other suite
containers; unrelated Watchtower workloads may continue. Repeating setup or
credential recreation preserves the approved directory, immutable image and
Watchtower deferral. Existing custom Nginx mode blocks baseline setup before
mutation; inventory its routes into supported service-registration fields and
regenerate standard routes through the owning workflow before adoption. Never
remove a custom marker merely to bypass that preservation gate.

## One-time bootstrap for an old, unselected proxy

An existing old proxy may lack the live updater policy that DC requires before
release import. Install the compatible **published** host CLI and proxy wheels
first, then provision the approved public release files as host root before
proxy plan/adopt. The host wheel alone does not repair the serving updater.
This is ordinary declarative file provisioning, not an updater API, private
lifecycle helper, or permission to patch capabilities or source labels.

Use this path only when the existing proxy is unselected: no selection ID/hash
in customer/public configuration, no `selection.json`, and no
`.lifecycle-publication.json` recovery journal in the actual release directory.
If any exists, stop and reconcile through its existing owner; never overwrite
policy, pins or recovery state. Coordinate a maintenance window with other
setup/import writers and updater jobs quiesced. Proxy adoption independently
checks its existing dispatch/operation locks and refuses occupied or queued
work before stopping the proxy.

The public DC setup/status/upgrade flow uses the canonical `/etc/dc-overview`.
For this procedure keep `customer.yaml`'s `config_dir` at `/etc/dc-overview` and
`release_selection.release_selection_dir` at `/etc/dc-overview/releases`.
Ordinary status/upgrade do not automatically discover alternate configuration
roots. The complete proxy declaration must use that same release directory.

1. Obtain the trusted, normally published `suite-release.json` and verify its
   publisher and artifact receipts. Compute its **actual byte hash**, without
   reformatting it:

   ```sh
   sha256sum suite-release.json
   ```

   A SHA256 match identifies bytes; it does not establish publisher trust.
   Test manifests, test wheel URLs/digests and source checkouts are not customer
   inputs. The selected proxy candidate must be the actual published image
   matching the installed compatible host proxy package, not a fabricated
   `direct_url.json`, label, version or capability assertion.

2. Author and review a complete `customer-selection.json`. Its only top-level
   fields are `schema_version`, `selection_id`, `manifest_sha256`, and
   `components`. Use schema 1, the reviewed manifest's `baseline_id` as the
   selection ID, and the exact lowercase 64-hex byte hash above. Every manifest
   component must appear **exactly once**, with no omissions or extra names.
   Each entry has boolean `enabled` and `origin`; only `customer-pin` also has
   `pin`. The example below assumes the manifest has exactly these twelve
   components and the customer enables only DC/Prometheus/Grafana plus the
   mandatory proxy and CLI. Replace the ID and zero hash and review every entry
   against the actual manifest and `customer.yaml`; do not copy these choices
   as site policy.

   ```json
   {
     "schema_version": 1,
     "selection_id": "REVIEWED_BASELINE_ID",
     "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
     "components": {
       "cryptolabs-proxy": {"origin": "baseline", "enabled": true},
       "dc-overview-cli": {"origin": "baseline", "enabled": true},
       "dc-overview": {"origin": "baseline", "enabled": true},
       "prometheus": {"origin": "baseline", "enabled": true},
       "grafana": {"origin": "baseline", "enabled": true},
       "ipmi-monitor": {"origin": "baseline", "enabled": false},
       "vastai-exporter": {"origin": "baseline", "enabled": false},
       "runpod-exporter": {"origin": "baseline", "enabled": false},
       "vast-price-manager": {"origin": "baseline", "enabled": false},
       "node-exporter": {"origin": "baseline", "enabled": false},
       "dc-exporter": {"origin": "baseline", "enabled": false},
       "dc-watchdog-agent": {"origin": "baseline", "enabled": false}
     }
   }
   ```

   Proxy and CLI must be enabled. DC requires Prometheus/Grafana; declared
   workers require node/DC exporters; an enabled installed Watchdog requires
   its agent. Align optional roles with the customer's actual component flags,
   worker list and Watchdog install choice. Preserve reviewed origins/pins.
   `baseline` follows the approved artifact; `customer-pin` is the exact OCI
   reference or bare worker/wheel SHA256 from that manifest, including disabled
   pinned entries. A conflicting pin holds. `unmanaged` cannot be enabled.
   JSON is bounded declarative data; commands, arbitrary owners, unknown fields
   and executable policy are unsupported.

3. From the directory containing those two reviewed files, provision root-owned
   directories 0755 and new public files 0644. These Linux/coreutils commands
   refuse an existing selection/journal, symlinks or incompatible existing
   directory custody, and never overwrite an existing policy. An already
   present immutable manifest is reused only when root-owned 0644 and byte
   identical. If a guard or copy fails, stop and inspect the retained files;
   do not delete existing state just to rerun the bootstrap.

   ```sh
   sudo sh -eu <<'SH'
   umask 022
   store=/etc/dc-overview/releases
   test ! -e "$store/selection.json" && test ! -L "$store/selection.json"
   test ! -e "$store/.lifecycle-publication.json" && test ! -L "$store/.lifecycle-publication.json"
   for directory in /etc/dc-overview "$store" "$store/manifests"; do
     if test -e "$directory" || test -L "$directory"; then
       test ! -L "$directory" && test -d "$directory"
       test "$(stat -c '%u:%g:%a' "$directory")" = '0:0:755'
     else
       install -d -o 0 -g 0 -m 0755 "$directory"
     fi
   done
   manifest_sha=$(sha256sum suite-release.json | cut -d ' ' -f 1)
   manifest_file="$store/manifests/$manifest_sha.json"
   set -C
   if test -e "$manifest_file" || test -L "$manifest_file"; then
     test ! -L "$manifest_file" && test -f "$manifest_file"
     test "$(stat -c '%u:%g:%a' "$manifest_file")" = '0:0:644'
     cmp -s suite-release.json "$manifest_file"
   else
     cat suite-release.json > "$manifest_file"
   fi
   test ! -e "$store/.lifecycle-publication.json" && test ! -L "$store/.lifecycle-publication.json"
   cat customer-selection.json > "$store/selection.json"
   test "$(stat -c '%u:%g:%a' "$store/selection.json")" = '0:0:644'
   sha256sum "$manifest_file" "$store/selection.json"
   SH
   ```

4. Inventory the old proxy's routes, domain, TLS, mounts and account authority
   into its complete supported `customer-proxy.json` declaration. Set
   `release_selection_dir` to `/etc/dc-overview/releases`; preserve the actual
   services, forwarding and certificate choices. Run the shipped host command's
   read-only plan, review its identities and preservation proof, then adopt that
   exact plan. Any policy/runtime drift requires a fresh plan; do not bypass a
   hold or replace the candidate with fixture bytes.

   ```sh
   sudo cryptolabs-proxy configuration plan --declaration customer-proxy.json
   sudo cryptolabs-proxy configuration adopt --declaration customer-proxy.json --plan-id REVIEWED_PLAN_ID
   ```

5. After successful proxy adoption, run ordinary DC setup/upgrade with the
   approved manifest. DC revalidates the installed CLI's exact public wheel
   provenance, complete selection, enabled roles, worker privileges/platforms,
   TLS/configuration and the live updater capabilities before mutation, and
   commits the public selection reference through its existing lifecycle lock
   and compare-and-swap boundary. File provisioning and proxy adoption alone
   do not establish full-suite or operator acceptance.

   ```sh
   sudo dc-overview setup --config customer.yaml --release-manifest suite-release.json
   sudo dc-overview upgrade --release-manifest suite-release.json
   ```

Check the **serving container** consumer before submission:

```sh
sudo docker exec cryptolabs-proxy env PYTHONPATH=/app/src python3 -m cryptolabs_proxy.updates capabilities
```

The compatible consumer returns
`{"selection_contract":1,"proxy_replacement_policy":"host-adoption-required-v1"}`.
Host wheel/module output does not certify an existing serving updater. Ordinary
DC preflight queries the live source and holds old/unknown capabilities. Generic
system `python3` may not import a package in the pipx environment; use the
installed host commands above for customers. The following are internal consumer-contract examples; the normal DC commands
coordinate the complete suite. Compatible host clients queue the existing
helper with the already approved selection ID and SHA256 of exact selection
bytes:

```sh
sudo docker exec cryptolabs-proxy env PYTHONPATH=/app/src python3 -m cryptolabs_proxy.updates submit --service all --action update \
  --selection-id APPROVED_ID --selection-sha256 EXACT_SELECTION_SHA256
sudo docker exec cryptolabs-proxy env PYTHONPATH=/app/src python3 -m cryptolabs_proxy.updates status JOB_ID
```

The existing `/api/update` and `/api/pull` accept `selection_id` and
`selection_sha256` alongside `service`/`branch`, retaining `{success,job}` and
202 on a queued operation. Both selection fields are mandatory together.
API requests cannot supply manifests, paths, commands or image references.
Explicit `dev` conflicts with a selected baseline; the existing `main` default
selects the approved vector. Legacy requests resolve installed policy when
present. A configured missing/invalid release mount fails closed and never
falls back to a channel. Without baseline policy, historical channel behavior
remains available.

Every enabled selection entry is required. Unknown IDs/owners/schema/platforms,
missing installed proxy-owned services, incompatible customer pins and enabled
unmanaged roles block before a helper starts. `baseline` may move an older
immutable image to the newly selected vector. `customer-pin` never moves to a
conflicting artifact. Disabled optional entries remain disabled.

The durable helper stores exact validated selection/manifest bytes in the
existing `/data/auth/update-jobs` volume. It revalidates the snapshot and reads
only the two fixed public policy files through the serving proxy's Docker
archive API. It stages exact pulls, verifies repository digest/platform, and
checks every planned clone before stopping any service. Runtime or policy
changes block execution. Replacement preserves deployed mounts/network/settings,
health verification and existing rollback behavior, with Watchtower false.

Jobs/results retain existing fields and add selection identity, `scope`,
`owner`, `origin`, `desired`, `observed` and `reason`. Unknown identity is null;
`update_available` is null when unverifiable. Success refers to the proxy-owned
scope. `suite_complete` remains false, and external VPM/CLI/worker owners have
explicit required outcomes. The proxy does not execute their Compose, package
or SSH operations. Final published digests, independently released compatible
consumers and real customer install/upgrade evidence remain release gates.
