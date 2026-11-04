# Scoped updater matrix proposal (not applied to unrelated pairing authority)

These IDs label unchanged owner-approved plan clauses; they do not introduce new requirements. Root must verify the mapping before production builder dispatch.

| Trace | Approved source/control | Implementation | Verification | Validation | State |
| --- | --- | --- | --- | --- | --- |
| TRACE-UPDATER-001 | REQ-UPDATER-001, approved plan clause 1 + reviewed amendments 1/5 | migration.py DockerEngine._request/stop; updates.py UpdateEngine._request timeout forwarding | VER-UPDATER-001, real socket regression + full default proof | VAL-UPDATER-001, disposable Docker and installed updater identity before retry | Actual pre-fix RED; no production edit |
| TRACE-UPDATER-002 | REQ-UPDATER-002, approved plan clause 1 + reviewed amendments 2/3/4 | updates.py replace_container safe phase/category capture | VER-UPDATER-002, actual run_job persistence and recovery cases | VAL-UPDATER-002, retained safe failure/recovery evidence in staging and intended workflow | Actual pre-fix RED; no production edit |

## Proposed Code Anchor Evidence

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
| --- | --- | --- | --- | --- | --- |
| src/cryptolabs_proxy/migration.py | REQ-UPDATER-001 | TRACE-UPDATER-001 | VER-UPDATER-001 | file-role | bounded-docker-stop-transport |
| src/cryptolabs_proxy/updates.py | REQ-UPDATER-002 | TRACE-UPDATER-002 | VER-UPDATER-002 | file-role | safe-update-recovery-diagnostics |
| tests/test_updates.py | REQ-UPDATER-002 | TRACE-UPDATER-002 | VER-UPDATER-002 | verifies | persisted-updater-failure-contract |
| tests/test_proxy_lifecycle_review_repairs.py | REQ-UPDATER-001 | TRACE-UPDATER-001 | VER-UPDATER-001 | verifies | real-stop-socket-deadline |

No source anchors authored during RED definition. tw-work must use the packaged anchor helper with these unambiguous approved-clause mappings, write source + matching matrix evidence together, then rerun its scoped scanner. Existing root authority is preserved; orchestrator chooses scoped merge before builder.
