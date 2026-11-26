# Storage-native retention qualification (developer-only)

`cmd/charter-retention-probe` is deliberately separate from Charter serving code. It is not a provisioning tool. Never point it at production, a public endpoint, or a bucket containing non-synthetic data. The CLI requires both `--execute` and the exact `CHARTER_RETENTION_PROBE_OPT_IN=I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB` acknowledgement. Its endpoint validator accepts only an HTTP(S) literal loopback IP address (not `localhost` or a resolvable name); the HTTP transport disables proxy use and refuses redirects. Buckets must be three distinct, pre-provisioned `charter-c04-*` names. Runtime-writer and administrator access keys are separate environment variables and are never printed. Do not pass credentials as command-line flags.

## Current implementation status

The standalone executable is the original **partial** probe; its explicit retention headers require a provider policy that allows setting retention on writes. The full default-only qualification is `scripts/retention-lab/seaweed-run.sh` in the owned offline VM. It exercises restricted credentials that lack `PutObjectRetention` entirely, verifies that the storage default applies, and uses a separately held administrator credential for genuine Object Lock refusals. It must not be replaced with the standalone CLI or mocked unit tests.

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

## Full synthetic storage command and pins

Build `charter` with `CGO_ENABLED=0 go build -trimpath -o charter ./cmd/charter`. Build the two mandatory binaries with `CGO_ENABLED=0 go test -tags retention_drill -trimpath -c -o retention-drill.test ./cmd/charter` and the same command with `-o retention-real.test ./internal/evidence`. Building those binaries does not run their qualification; hosted CI runs the regular Go/Python and PostgreSQL suites, not the no-NIC lab.

Stage the scripts in `scripts/retention-lab/`, the three binaries, `scripts/provision-runtime-roles.sql`, the pinned SeaweedFS executable named `weed`, and a `docker save` archive named `postgres-16.16-alpine.tar.gz`. Generate `ARTIFACT-SHA256SUMS` for the payload; mount it read-only at `/mnt/rgw-payload`. Use a fresh Ubuntu 24.04 amd64 guest with no NIC, no default route, Docker 28.5.2 configured with `bridge=none`, and a separate evidence volume labeled `RGWQ110EVID`. Invoke `bash /mnt/rgw-payload/seaweed-run.sh` as the lab provisioner. Check the separate evidence volume for zero native exit, `FULL_CHARTER_DRILL_PASS`, and matching version/content inventories. A shutdown, missing report, nonzero native status, failed control, or INCONCLUSIVE mandatory operation is not a successful lab run. Do not reuse the runner against any other storage service.

SeaweedFS release 4.55, linux amd64, source `a98c9e27185cf1003eca095761a39973c60734db`; release archive SHA-256 `f156c609eeaf9e5fcfeea33fd70411222005f83760aa95893c9d58eff006b45c`; executable SHA-256 `b0e48a0d0bd26d206cc4e96b3edcfebded8086b47d77f619b9a676f4f51abd36`. PostgreSQL 16.16 Alpine manifest `sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d`, imported image ID `sha256:a3c40a6a77a9a545ed6d766860c45f82ab8bc254148266e56c4139f91beec635`. Docker static archive SHA-256 `ea90cfd12e1eeb12aa1c971741adb8bd4ed88e2a574eaac13f5029a1dbc6300d`. The bucket default is one day in COMPLIANCE, with a 600-second serving minimum and a 35-minute signed synthetic activation window. A canary is provisioned separately with two-hour compliance retention. These are technical synthetic intervals, not legal retention periods.

Ceph RGW 20.2.5 (`ed27c686770872022f4c1de04f6b0ac5d5384ded`; amd64 image manifest `sha256:b2f0255d0e2626473e72f2ded7e67dfaf546272f1c6fa699e1aaffce288b6e57`) did not qualify: a six-round, 32-writer real test returned `[8, 32, 1, 32, 4, 1]` distinct successful versions on fresh conditional-create keys. The pinned code checks current-version state before preparing the per-version object write (`RGWRados::Object::Write::_do_write_meta` / `check_preconditions`); the observed semantics did not provide a serialized single winner. A versioned Object Lock bucket is not by itself evidence of this prerequisite. Administrator shortening on that run was also inconclusive (`MalformedXML`).

The signed activation statement is a trust input supplied by the independent provisioner. It binds the provider deployment, bucket, endpoint, report digest, writer identity digest, separate commit public key, required controls, validity window, and exact-version authority-canary receipt. The serving process runs without the qualification signer, provisioning credential, or PostgreSQL owner credential. It checks the scope and canary on startup and readiness and before evidence writes; it does not continuously repeat destructive or IAM administration probes. Re-provision and requalify after changes in runtime grants, storage policy, version, deployment identity or protected bucket. This activation is not external chain anchoring or a claim against administrators of the VM, disks, clocks, or storage binaries.
