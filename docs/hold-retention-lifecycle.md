# C07: Hold, deletion and retention lifecycle

Implements issue #7 per ADR 0001 section 7 and the [state machines](contracts/state-machines.md).
Nothing here is a legal-compliance claim; this is the technical preservation
contract tested by the pilot drill.

## Scope and authorization

A hold is an authorized, tenant-scoped claim over a matter selection:

- `matter_id` (required, must map to a project of the caller's tenant),
- optional `custodian_ids` (empty = all custodians of the matter),
- optional `[window_start, window_end)` applied to the evidence `recorded_at`
  (`window_end` null = open ended: future matching work is covered until release).

Only `records_officer` places, changes, releases, sweeps, approves disposal or
inspects hold records (`internal/records`, `POST /v1/holds`, `GET /v1/holds`,
`PUT /v1/holds/{id}`, `POST /v1/holds/{id}/release`, `/v1/retention/*`).
`tenant_admin`, `operator`, `export_reviewer` and project members are refused
(403), and every mutation re-verifies the role inside its transaction after
taking the tenant row lock. Cross-tenant identifiers and matter substitutions
fail closed (indistinguishable from nonexistent). Disposal approval requires a
records officer OTHER than the one whose sweep requested it.

**Held is derived, never stamped**: an item is held iff an active hold
(pending, effective or failed) matches it. Custodian revocation changes
workspace access only; holds scoped to that custodian keep applying.

## Lifecycle states and the activation boundary

```
requested (in-flight request) -> pending --establish+verify--> effective
pending --establishment failure--> failed (retryable; the fence stands)
effective --release by records_officer--> released
```

- **pending**: the hold epoch is committed - disposal is fenced - but
  storage-native protection is not yet verified. This is the acknowledgment
  boundary of ADR 0001: any disposal that observes the epoch can no longer
  touch matching items.
- **effective**: acknowledged only after every in-scope version's legal hold
  is set AND read back ON. An establishment failure never downgrades: the hold
  records `failed` with the exact error and uncovered records, and retries
  idempotently.
- **released**: removes only that hold's claim. Overlapping holds keep their
  protection; storage legal holds are cleared only for versions no remaining
  hold or non-disposed referencing record requires (release cleanup is
  conservative: a failed cleanup leaves protection in place and records the
  pending versions).

The durable coverage report records every in-scope item with
`already_expired` flags, `disposed_before_hold` gaps (a hold placed after
disposal is a recorded miss, never a silent one) and `uncovered` records whose
versions could not be verified (which block the effective transition).

## New matching work

The recorder carries a lifecycle guard (`evidence.TurnLifecycleGuard`, wired
in `cmd/charter`). Hold protection is enforced after admission and
immediately before release, using the turn's exact event-0 identity: if an
active hold matches, every version published so far is legal-held and the
readback verified BEFORE the turn may proceed; a protection failure fails the
turn closed (nothing is released). The pre-release check closes the window
where a hold commits while the turn is in flight; the placement's own
post-commit scan covers everything admitted earlier. No successful response
escapes without its required hold protection.

## Storage enforcement (retained S3 profile)

The hold lifecycle uses the storage's NATIVE legal hold on exact versions,
applied through a records-scoped credential (`CHARTER_S3_RECORDS_*`) that is
bound by the qualification statement's `records_access_key_sha256`. The
serving runtime credential deliberately holds none of these permissions (C04
qualification controls). Verified against the pinned SeaweedFS 4.55:

- legal hold ON blocks version-specific deletion even after retention expiry
  and even with a governance-bypass header; OFF permits deletion once the
  base COMPLIANCE retention has expired;
- base retention is only extendable, never shortenable, and remains after a
  release (release does not override base retention);
- deletes are version-specific and idempotent (absent = already gone);
- shared content-addressed objects are never deleted while another
  non-disposed record references them (`retained_shared` outcome).

Disposal (`disposal_pending -> purging -> disposed`) is the ADR two-phase
conditional delete: `begin_purge` re-evaluates holds under the matter epoch and
tombstones (unreadable; bytes retained); `finish_purge` locks the matter epoch
row FOR UPDATE for the whole transaction including the irreversible storage
deletes, so a hold acknowledged before the delete commits always wins, and a
hold committed after observes a disposed item and records the gap. On an epoch
mismatch the purge restarts (`stale_retry`) or is restored (`restored_active`);
bytes that already vanished are reconciled to `disposed` conservatively. If
the storage still protects a version (base retention unexpired), disposal is
blocked and reported - physical deletion is never claimed while protected
versions remain. The PostgreSQL profile does not support disposal (its
evidence tables are append-only by trigger): purge is refused, honestly.

## Concurrency and recovery

- Placement, release and scope change serialize on the per-matter epoch row;
  disposal locks the same row across its deletes (the conditional-delete
  fence). Interleavings A-G of the state machines are executable tests.
- Concurrent sweeps are idempotent (exactly-once marking); concurrent
  same-key placements create exactly one hold, one epoch and one audit row;
  overlapping releases are idempotent; concurrent purge finishes dispose
  exactly once.
- Deterministic barriers (`records.Store.Hooks`) freeze a lifecycle
  transaction at its epoch lock so races are reproduced without sleeps.
- Recovery (`records.Service.Recover`, at serving start, no user
  authorization, no workspace tables): re-establishes pending/failed holds,
  retries release cleanup, completes interrupted conditional deletes, and
  conservatively marks items whose bytes verifiably vanished. The
  crash-window between a committed storage delete and the uncommitted
  transaction is recovered idempotently (absent versions complete the
  disposal); a hold landing in that window records `disposed_before_hold`.
- Workspace deletion (chat/project) and custodian revocation are
  workspace-tier only: evidence, holds and the lifecycle catalog are separate
  stores the workspace credential cannot write or read.

## Residual limitations

- Storage administrators with raw credentials outside Charter remain a
  residual risk (ADR 0001 section 12) - legal hold is enforced against
  Charter's own credentials, including the records transport.
- The retained runtime write path inherits the bucket-default retention floor
  (1 day): disposal of serving-path evidence can only complete after that
  deadline; the drill's disposal-eligible controls are admitted through the
  records-write transport with short explicit retention (documented in the
  drill and the qualification report).
- `pending` holds fence disposal but records-officer content access requires
  a matching hold in any active state; see the role matrix for content scope.
