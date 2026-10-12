# Controller adoption exclusion

Published host clients may use `AdoptionEngine.controller_guard(source_proxy,
image_id, operation_id, recover=False)` for supported DC monitoring adoption.
The serving proxy must advertise this exact `controller_adoption_guard` value
through its existing updater capabilities command:

```json
{"schema_version":1,"api":"AdoptionEngine.controller_guard","durable_updater_exclusion":true}
```

Use `UpdateEngine.updater_capabilities(source_id)` to query the exact running
proxy. A host import alone does not prove support. The caller must also verify
the selected published artifact and serving source identity before adoption.
`image_id` must equal that proxy's immutable `Image`. Use a stable operation ID
matching `[A-Za-z0-9][A-Za-z0-9_.-]{0,95}` and persist the private host recovery
record before entering the guard.

The fixed stdlib helper mounts only the exact writable `/data/auth` store. It has
no network, Docker socket, auth startup, or inspected environment. It acquires
the existing `update-jobs/dispatch.lock` then `operation.lock`, without replacing
those inodes, within a bounded deadline. Before yielding it atomically writes
and fsyncs a private `controller-adoption.json` marker. The marker binds the
operation, source container/image, auth mount and current helper custody.

Call the yielded callable immediately before and after each Engine mutation or
long validation step. Each single step must finish within the fixed five-minute
helper lease. Successful checks refresh that lease. Idle expiry removes the
helper process and releases its locks while retaining the incomplete marker;
matching recovery can then reacquire exclusion. Later checks and completion fail
closed after helper expiry. Each call uses the configured Engine socket for
exec create/start/inspect,
without ambient Docker CLI context or host selection. The bounded non-TTY
response is demultiplexed and accepted only after exact helper/exec/process
identity and successful exit are verified. It checks the exact helper's liveness
and asks that helper to prove its retained
lock inodes, private directory and marker custody. A dead helper or changed
custody holds subsequent writes. The caller owns monitoring file locks and
terminal service verification.

Call `check.complete()` only after a verified terminal host state has been
recorded. This verifies current ownership and durably removes the marker;
repeated completion is idempotent on the same live guard. Further `check()`
calls fail after completion. Context exit removes the helper and always leaves
an incomplete marker in place, including after an exception. Ordinary
updater submission, worker execution and host proxy configuration adoption all
refuse the persisted marker even after
the helper has died; a queued worker records a blocked outcome.

`recover=True` reacquires the same real locks and accepts only a matching
operation/source/image/mount marker. A positively absent marker under those
locks is also safe to establish for recovery of a prepared host record. Unknown,
conflicting, oversized or unsafe markers hold. Active lock owners are never
stolen. Marker inspection uses bounded no-follow reads; updater directories and
locks must have their product-created private ownership and permissions.

This API coordinates the normal proxy updater. External Compose or Watchtower
owners require the affected services' declared maintenance procedure. It does
not claim atomic cross-service changes or restore shared auth state.
