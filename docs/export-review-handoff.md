# C08 reviewer handoff: portable held evidence

C08 is a technical exchange format. It is not a legal admissibility decision,
regulatory certification, or a Purview/Relativity ingestion or load-file format.
No external legal service is required. Use only an authorized case workspace or
private local volume for the bundle and its copies. Reviewers can verify the
handoff without a Charter login, runtime, database, IdP, or network access.

## Obtain and verify the package

1. Ask the case custodian to supply the export ID, snapshot ID, evidence
   profile, and expected `sha256:<64 lowercase hex>` manifest digest over a
   separately authenticated case channel. A records officer can read this
   digest from the successful generation response (or query the same request
   by its original idempotency key, while authorized). A digest taken from
   the package, or simply recomputed over it and passed as its own expected
   digest, is not an independent anchor. Check that the ID and digest in your
   control record refer to the intended transfer. The package response's
   digest header is useful for transport comparison, not by itself an
   independent channel when forwarded together with package bytes.
2. Use the prebuilt verifier from your trusted tool distributor, or build from
   a trusted Charter checkout for Linux with the Go version in `go.mod`:

   ```sh
   CGO_ENABLED=0 go build -o charter-verify ./cmd/charter-verify
   CGO_ENABLED=0 go build -o charter-export-unpack ./cmd/charter-export-unpack
   ```

   Building from source may need previously cached Go modules; the built
   executables do not fetch anything. Verification requires a Linux filesystem
   with `/proc/self/fd` available, not a Charter deployment.
3. If the custodian supplied the authenticated HTTP transport representation
   rather than the already materialized directory, unpack into a *new*
   directory in a trusted, private parent. The transport is a JSON map of
   fixed bundle-relative names to canonical standard-base64 values; it is
   not an archive and does not establish permissions or extract links.

   ```sh
   ./charter-export-unpack -out ./case-export \
     -profile charter-s3-compliance-v1 -manifest-sha256 "$TRUSTED_DIGEST" \
     < ./charter-export.json
   ```

4. Run verification on the directory and keep its machine-readable result
   with the trusted control record. Repeat verification on each downstream
   copy against the same expected digest. Do not normalize JSON, line endings,
   names, or object bytes. Do not use extraction or copying that adds links or
   merges into directories containing unrelated files.

   ```sh
   ./charter-verify -bundle ./case-export \
     -profile charter-s3-compliance-v1 -manifest-sha256 "$TRUSTED_DIGEST"
   ```

| Exit | Meaning |
| --- | --- |
| 0 | Complete verified package relative to the authenticated frozen selection. |
| 2 | Authenticated package with explicit gaps or uncovered records; not complete. Inspect `result.gaps`. |
| 3 | Integrity failure (e.g. bad anchor, changed/missing member, or invalid sequence). Do not rely on the package. |
| 4 | Unsupported schema/profile; obtain the correct trusted tool. Never retry with a weaker profile selected by the bundle. |
| 5 | Operational or invocation failure; retry after resolving the environment or arguments. |

There is no unauthenticated success mode. The digest authenticates the
submitted manifest relative to an independently trusted comparison value. An
adversary who replaces the manifest and all internal bytes can compute a new
consistent digest; they cannot make that replacement match a trusted original
SHA-256 digest. Offline verification does not prove administrative storage
immutability, upstream source authenticity, a legal chain of custody outside
Charter, or completeness beyond the authenticated selection. Charter does not
attach an external transparency log, timestamp, or self-trusted public key.
The production retained marker signing key protects storage readback; the
export manifest is not signed with it. Already delivered bytes cannot be
revoked or deleted by Charter.

## Bundle layout and semantics

- `manifest.json`: exact canonical UTF-8 JCS-compatible JSON (Charter's RFC
  8785 integer subset); no trailing whitespace. Schema `charter-export-bundle-v1`.
- `events/<canonical-lowercase-UUID>.jsonl`: original canonical event bytes
  plus one LF per event, in sequence order. No empty substitute logs for
  missing turns.
- `objects/<64 lowercase hex>`: raw bytes, deduplicated by SHA-256; references
  and the original event lineage are not deduplicated away.

The manifest binds `schema_version`, `profile`, `export_id`, `snapshot`,
`scope`, `custody`, `turns`, `objects`, and `gaps`. The retained profile also
requires `custody_audit`. No unknown fields or extra
files are accepted. `scope` supplies scoped tenant/project/matter IDs,
explicit custodian allowlist, and half-open UTC `window_start`/`window_end`.
The time window selects admissions, not the later events of an admitted turn.
`snapshot` binds `id`, `revision` (decimal matter hold epoch), `captured_at`,
and `hold_ids`. `custody` binds `requester_id`, `approver_id`, `requested_at`,
`approved_at`, and `snapshot_id`.
`custody_audit` uses `version: scoped_projection_v1` and exactly two `rows`
in append sequence: `export.request`, then `export.approve`. Each row carries
decimal `id`, UTC `at`, `action`, `actor_id`, `tenant_id`, `export_id`,
`snapshot_id`, and the shared `intent_digest`. This is a whitelist projection
of the append-only journal for this tenant and export, not a raw audit-log
dump. The projection is read at generation admission. Unrelated payloads and
free-text reasons are not copied. Publication and retrieval postdate this
projection; they remain in Charter's journal, not inside the bundle whose
digest they reference. The independent anchor binds the projection but does
not let an offline verifier inspect the live journal. The two actors must differ. Values represent
Charter's control-plane record, not a reviewer attestation or legal finding.

Each turn supplies `turn_id`, `custodian_id`, `recorded_at`, `hold_ids`,
`event_path`, `event_sha256`, `event_count`, `end_sequence`, `head_hash`,
`partial`, `missing_sequences`, and `retained_versions`. Each retained-version
entry binds `key`, `version`, `kind`, `sha256`, `bytes`, and `source`. `signed`
means the producer checked a retained signed marker; `plan_readback` means
the exact surviving bytes were identified from an authoritative disposal
plan and verified against their original hash, but the producer did not have
the associated signed marker. Storage keys identify
retained artifacts; they do not grant access. Per-object declarations bind
`sha256` and `bytes`. Strong full-profile verification checks original input
and exact sealed context where disclosure occurred, output/artifact bytes,
policy/routing/accounting and source lineage as captured. A source excerpt is
not a preservation copy of the entire source library. A provider-visible
request is not reconstructed from a workspace summary. Neither original
object bytes nor hashed event payloads are silently redacted.

Gap entries bind `turn_id`, `kind`, `custodian_id`, `recorded_at`, `hold_ids`,
and `missing_versions`. Historical loss must identify exact `key`, `version`,
`disposition`, and `plan_epoch` (null only if unavailable in the retained plan).
A plan alone is not loss. `partial_loss` only establishes the verified
surviving material; broken chain segments do not get a whole-chain verdict.
`complete_loss` and `disposed` do not fabricate event records. `uncovered`
identifies an in-scope admission for which no matching effective hold supplies
export authority; it must not be interpreted as verified historical loss.
Unreadable or otherwise unknown authority/presence is an operational refusal,
not a gap declaration.

A `disposed` gap may additionally bind `retained_shared_versions`: exact
content-addressed object versions that physically survived the record's
completed disposal through another record's references. Each entry identifies
`key`, `version`, `disposition` (always `retained_shared`) and `plan_epoch`.
This is attribution, not content: the bytes are not exported through the
disposed record's identity, the same exact version is never also declared
missing, and the entry asserts neither presence nor absence today - it records
the durable disposal ledger's outcome. The surviving version's protection is
the retaining record's responsibility. No other gap kind may carry
`retained_shared_versions`; a non-disposed record's shared bytes appear, when
authorized, as that record's own `retained_versions` content.

## Service custody and linearization

- The records officer posts `POST /v1/exports` with `Idempotency-Key` and
  `project_id`, `matter_id`, `custodian_ids`, `window_start`, `window_end`,
  and `reason`. A retry of the same key and intent does not recapture. Changed
  intent collides; use a new key after an authority change. Tenant identity
  comes from the accepted principal, never the JSON body.
- A different active reviewer posts the returned `snapshot_digest` (bare
  lower-case hex) to `POST /v1/exports/{id}/approve`. The original officer
  posts to `.../generate`, and only the bound approving reviewer may use
  `GET .../package`. The original officer may `POST .../cancel`.
- Request/approval, generation lease, publication, cancellation and delivery
  authorization each linearize at their audited database commit. The lock
  order is tenant authority, tenant protection, selected retention rows,
  and matter hold epoch. Later captures cannot change a frozen selection.
  Hold changes invalidate the older epoch, even if another overlapping hold
  remains. Disablement and role revocation deny delivery; later role grants
  do not resume the previous role instance's package authority.
- Only a finite generating lease permits staging, entirely in process
  memory. The same verifier checks the staged result before the audited
  ready transaction stores it. A crash before that commit leaves no
  retrievable copy. The next reconciler converges an abandoned lease to
  approved for explicit retry; a verification rejection is terminal. An
  approved reviewer gets no content on a failed authorization or audit
  commit. A retrieval audit means a release was authorized, not that the
  reviewer received or retained every HTTP byte.
- Package bytes are stored in the restricted workspace control database;
  no public path, credential, or download URL is created. Requests and
  packages share a fixed deadline of 24 hours from request. Automatic
  reconciliation removes expired package bytes; cancellation removes bytes
  atomically. The append-only audit trail and immutable request metadata
  remain. Deleting a database value is not a promise of immediate secure
  erasure from storage media or backups.

Paths are strictly fixed, ASCII and bundle-relative. Absolute members,
traversal, non-regular files, symlinks (including bundle path ancestors),
hard links, undeclared paths, ambiguity and duplicate JSON keys are refused.
Current verifier limits: 32 MiB verified member bytes, 4 MiB manifest,
10,000 member files, 16,384 events, two directory levels from the selected
root including member files. The HTTP transfer is capped at 32 MiB; generation
caps raw evidence at 20 MiB, with separate snapshot and exact-ref limits.
Future incompatible schema/profile changes require a new explicitly selected
version. An older verifier will refuse versions it does not support.
