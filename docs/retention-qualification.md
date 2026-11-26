# Storage-native retention qualification (developer-only)

`cmd/charter-retention-probe` is deliberately separate from Charter serving code. It is not a provisioning tool. Never point it at production, a public endpoint, or a bucket containing non-synthetic data. The CLI requires both `--execute` and the exact `CHARTER_RETENTION_PROBE_OPT_IN=I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB` acknowledgement. Its endpoint validator accepts only an HTTP(S) literal loopback IP address (not `localhost` or a resolvable name); the HTTP transport disables proxy use and refuses redirects. Buckets must be three distinct, pre-provisioned `charter-c04-*` names. Runtime-writer and administrator access keys are separate environment variables and are never printed. Do not pass credentials as command-line flags.

## Current implementation status

The executable validates the synthetic opt-in/configuration, verifies protected-bucket versioning and Compliance Object Lock default retention, and uses a fresh random `charter-c04-<random>/` prefix for all written object keys. It then creates a protected synthetic object through the runtime identity; proves an administrator retention-extension positive control; attempts administrator shortening, administrator exact-version deletion, and runtime exact-version deletion; and checks the original exact version, SHA-256, Compliance mode, and retain-until readback after each attempt. It also performs one 32-request synchronized conditional-write round against an occupied key and one against an empty key, checking the version count and winner count. The command does not provision infrastructure or modify bucket policy/configuration. No live or loopback endpoint was exercised while implementing this code; the results below are code/test verification only, not provider enforcement evidence.

The Go SDK dependency is pinned by the repository module lock. The protected and control buckets must be created and configured out of process; this CLI must never create buckets or grant permissions.

## Required lab layout for a future full qualification

Provision isolated synthetic buckets and policies before running the full harness:

- **Protected bucket:** versioning and Object Lock enabled, Compliance default retention; pin its name in `CHARTER_RETENTION_PROBE_PROTECTED_BUCKET`.
- **Unprotected bucket:** versioned, no Object Lock; pin in `CHARTER_RETENTION_PROBE_UNPROTECTED_BUCKET` for explicit positive controls only.
- **Disjoint control bucket:** synthetic bucket with no production objects; pin in `CHARTER_RETENTION_PROBE_CONTROL_BUCKET`. Policy/lifecycle/configuration negatives must be isolated here and must not grant permissions.
- Runtime identity: `CHARTER_RETENTION_RUNTIME_ACCESS_KEY` and `CHARTER_RETENTION_RUNTIME_SECRET_KEY`.
- Administrator identity: `CHARTER_RETENTION_ADMIN_ACCESS_KEY` and `CHARTER_RETENTION_ADMIN_SECRET_KEY`.
- Endpoint/region: `CHARTER_RETENTION_PROBE_ENDPOINT`, `CHARTER_RETENTION_PROBE_REGION`.

Use an S3-compatible implementation only after verifying that its Object Lock and versioning semantics match the intended service. Never copy a real credential into a report. Ensure the lab is disposable and contains only harness-owned keys.

## Required result contract before relying on this tool

Each mutation must have a machine-readable `REFUSED`, `ALLOWED`, or `INCONCLUSIVE` result. For a refused mutation, the harness must independently read back the exact original version id, body SHA-256, retention mode and retain-until time. A service error alone is not evidence of refusal. If the original object cannot be verified byte-for-byte and retention-for-retention, classify the attempt `INCONCLUSIVE`. Every object key must include the fresh random run prefix and be created successfully by the harness before it is mutated.

The complete planned matrix includes:

1. Runtime identity: exact-version deletion, delete-marker attempt, retention shortening/removal/downgrade, bypass, and attempted bucket versioning/lifecycle/policy/configuration writes. Policy tests may only attempt no-op writes equivalent to existing policy or restrictive synthetic policies on the disjoint control bucket; never test a permission grant.
2. Administrator: delete exact protected version and shorten active Compliance retention; both must be refused with original version/SHA256/retention readback. Positive controls must be limited to exact deletion in the unprotected bucket and accepted retention changes/extension controls on harness-created, unprotected synthetic data as supported by the service.
3. Versioned concurrency: on a dedicated harness key, run at least 32 synchronized conditional creates per round for multiple rounds, then independently list/read versions and assert exactly one winner and one version. Do this before relying on conditional-write behavior in product code.
4. Sanitized report: endpoint hostname, bucket identifiers, random run id, probe names/statuses, SDK/service support gaps, and no credential values, authorization headers, raw SDK error bodies, or secret-bearing config.

## Explicit gaps

Not implemented: runtime delete-marker, retention removal/downgrade, governance bypass, bucket versioning/lifecycle/policy/configuration probes; administrator exact deletion/shortening of separate synthetic objects beyond the three-op protected-object path; allowed exact-version deletion and accepted retention controls in the unprotected positive-control bucket; restrictive-policy controls in the disjoint bucket; and multiple conditional-write race rounds. Results are human-readable status lines rather than a machine-readable report, and the race census checks the freshly created unique keys without paginated traversal (the expected population is at most one exact version per such key). Keep this a partial qualification harness: a successful run supports only the operations it actually reports and must not be described as a full storage-native retention qualification. A provider run has not been performed by this change.
