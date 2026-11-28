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

## The tenant protection fence (review correction)

Every native legal-hold mutation (set and clear), every disposal version
delete and every capture-side reference acquisition holds a per-tenant
`tenant_protection` row FOR UPDATE across its storage operations
(migration 0009). This is the single serialization point that makes removal
and establishment unable to use incompatible snapshots:

- a clear decision (which versions still have a remaining holder) and the
  clear operation run under the fence in one transaction; an establishment
  (set) or a capture cannot interleave between them;
- a newer hold's claim either committed before the fence was taken (it is
  visible to the clear decision - pending and failed claims also fence) or
  its establishment is serialized after the clear (its set happens once the
  fence is released), so an effective hold never loses required native
  protection - including cross-matter references to shared
  content-addressed versions;
- the recorder takes the same fence (the `ReferenceFencer` half of the
  lifecycle guard) around every evidence write that acquires a reference to
  content-addressed object versions: turn admission, event append and object
  staging. A new reference can therefore never be acquired between a
  disposal's shared-reference snapshot and its irreversible deletion of the
  exact required version.

The global lock order is tenants -> tenant_protection -> retention_items ->
matter_hold_epochs, and every path acquires in that order only: no new
deadlock is possible (the pre-existing epoch/items inversion in placement
and scope change is also fixed).

## Durable protection ownership and disposal plans (review correction)

- `hold_version_claims` is the durable protection ownership ledger. Every
  path that establishes protection for a hold - initial establishment, scope
  reestablishment, and the recorder guard protecting future matching work -
  records its exact version claims BEFORE the storage mutation is
  acknowledged. Release cleanup and crash recovery derive what must be
  cleared from the ledger, never only from a historical coverage report.
  Reconciliation (`reconcileClaims`) clears a claim's legal hold only when
  no remaining protection requires that version - counting every active
  hold of the tenant (pending, effective or failed), every non-disposed
  referencing turn, and using expiry-TOLERANT enumeration so already-expired
  references still fence. It runs at release, after scope change, and in
  recovery, so protection converges from every interruption boundary.
- `disposal_plans` is the durable exact-version disposal plan, committed by
  the plan phase of `finish_purge` BEFORE any irreversible deletion: an
  interrupted deletion resumes from the plan without requiring
  already-deleted enumeration metadata (the admission marker can be gone),
  and every planned version receives a verified disposition (`deleted`,
  `absent`, `retained_shared`, `protected`) in the same transaction that
  marks the item disposed.
- Scope revision binding: a scope change moves `holds.epoch` to the new
  matter epoch, and the effective transition (MarkEffective) is bound to
  the exact scope revision the establishment verified. A stale
  establishment completing after a scope change cannot mark the newer scope
  effective; the hold stays pending and re-establishes. MarkEffective is
  also the single authoritative acceptance rule: a report with ANY
  uncovered record is refused at the durable transition itself - initial
  placement, scope-change reestablishment and startup recovery cannot
  acknowledge incomplete protection.
- Disposal eligibility requires a VERIFIED terminal capture state (the
  backend's TurnTerminal): an admitted, actively executing turn is never
  swept into disposal by ordinary expiry, and a turn whose terminal state
  cannot be verified fails closed (never marked).
- Presence classification (`present` / `partial` / `absent` / `unknown`): a
  storage failure is never converted into proof of disposal. Only
  plan-verified absence may complete a disposal; unknown observations
  surface as errors and retain conservative state; partial disappearance
  (e.g. the admission marker gone while sibling versions survive) is
  reported and retained, never claimed as disposal.

## Round-2 review corrections (the remaining preservation-critical findings)

- **Coverage is the authoritative union** of the live evidence inventory,
  the durable lifecycle catalog and the durable disposal plans: a matching
  record whose live enumeration root is gone is covered from its plan
  (reported `partially_disposed` with the storage-verified losses counted
  and the remaining versions protected); a root-gone record WITHOUT a plan
  is `uncovered` and blocks the effective transition; a catalog-loading
  error fails the establishment instead of becoming an empty catalog. No
  record is silently omitted because its normal enumeration root is
  missing.
- **Every terminal capture path protects matching evidence**: the recorder
  establishes hold protection after the terminal event of denied,
  C06-refused, provider-failed, release-vetoed, interrupted and recovered
  turns (not only on the successful release/delivery path), and lifecycle
  recovery (`Recover`) re-establishes the full coverage of EFFECTIVE holds,
  repairing missing native protection without any client replay. A
  protection failure on a terminal path is logged durably and retried by
  recovery; the turn's evidence is never discarded.
- **Namespace fallback reference resolution is classified**: verified
  complete references, authoritatively established absence, known partial
  references backed by durable plans, and UNKNOWN references (transient or
  permanent marker read/verification failure). An unknown sibling
  reference set refuses the irreversible deletion (shared-reference scan)
  and the protection removal (required-version scan): an unreadable
  reference is never an absent one. A missing slot in the namespace
  sequence, an unreadable or unverifiable listed marker, and a slot key
  holding only delete markers all count as unknown references.
- **Plan restoration requires verified completeness**: a restore to active
  over a plan with outstanding entries verifies EVERY planned version by
  actual storage readback. Partial physical deletion restores with the
  loss recorded in the plan (`restored_active_partial`; the
  exact-version inventory is never destroyed) and protects the remaining
  bytes; every planned version gone completes the disposal honestly
  (`disposed_ambiguous`); the plan is cleared only for verified-complete
  restorations and completed disposals. Physical absence claims require an
  actual storage readback after each delete - a successful DeleteVersion
  response alone is never proof of disposal.
- **Placement idempotency is bound to the authorized intent**: a reused
  idempotency key is acknowledged only when the retry carries the exact
  matter, custodian selection, time window, reason and placing officer of
  the admitted hold; a changed intent fails explicitly (409) instead of
  acknowledging an unrelated existing hold. Identical retries return the
  original durable operation with no duplicate hold, epoch bump or audit
  row, and actor attribution is preserved.
- **The claims ledger owns every native mutation**: protection completion
  (MarkClaimProtected) requires an updated claim row; a hold that becomes
  applicable between the capture guard's claim phase and its native phase
  receives its durable claims in the same protection-fence transaction,
  before the storage mutation; the sweep covers active catalog records
  whose live root is gone, so a partially disposed record restored to
  active stays disposable through its durable identity.

## Round-3 review corrections

- **The namespace fallback enumerates the admission marker** (finding 1):
  the admission commit is the only place a turn's input objects are
  referenced (sequence-0 content-addressed receipts), so the fallback
  reference set of a chain-broken sibling includes the admission slot,
  its event data and its input objects whenever the admission is present
  and verifiable - a sibling's admission-only shared object is never
  silently absent, cross-matter alike. An admission that is present but
  unreadable, unverifiable or ambiguous (two admissions claiming one
  turn) is an UNKNOWN reference set: the irreversible deletion and the
  protection removal are refused. A gone admission stays a deleted root:
  the durable disposal plan governs the turn (the round-2 R4 convergence
  is preserved) and genuinely verified complete reference sets are never
  wedged.
- **Newly applicable ownership claims commit BEFORE the native mutation**
  (finding 2): EnsureProtected's second phase is two transactions under
  the tenant protection fence - a claims-commit transaction followed by
  a native-mutation transaction that revalidates every applicable hold
  has a COMMITTED claim row for every version before any SetLegalHold (a
  successful UPDATE inside an open transaction is not proof of durable
  ownership). A crash or rollback after the native mutation always
  leaves a committed claim that release cleanup and recovery converge;
  repeated applicability changes retry a bounded number of times and
  then fail closed with no native mutation.
- **Plan-backed terminality** (finding 3): sweep eligibility accepts a
  non-empty durable disposal plan for the exact turn as positive durable
  proof of previously verified terminality (plans are only committed by
  the authorized disposal lifecycle after a verified terminal capture
  state, and terminality is monotonic). An interrupted disposal whose
  terminal event data or marker was deleted therefore still resumes
  after release; in-flight captures (no plan) are decided by the live
  probe alone and fail closed. Coverage reports count previously
  dispositioned plan rows as missing versions (a durable record of loss
  is a loss, not intactness).
- **Effective-hold repair state is always visible** (finding 4): recovery
  of an effective hold distinguishes PENDING repair (uncovered records
  with a nil error: `repair_pending` in the durable report plus an
  attributable `hold.protection_repair_pending` audit row), FAILED
  repair (a coverage error: `repair_error` plus
  `hold.protection_repair_failed`) and VERIFIED repair (a subsequent
  successful pass resolves the outstanding state with
  `hold.protection_repair_complete`; the append-only audit trail keeps
  the historical evidence). Repair-state writes are bound to the hold's
  current scope revision, so a stale recovery result can never overwrite
  a newer scope's coverage information.

## Round-4 review corrections

- **The durable disposal plan is the AUTHORITATIVE reference set
  throughout interrupted disposal** (finding 1, CRITICAL): the exact
  version set evaluated for shared-reference protection is the UNION of
  the live enumeration and the plan's outstanding rows (every
  disposition except `deleted`/`absent`), so it always covers the
  deleter's version set. A live enumeration that SUCCEEDS can be
  TRUNCATED - a deleted suffix shrinks the chain-contiguity horizon, so
  `TurnDisposalRefs` walks only the surviving prefix - and a truncated
  result is never allowed to override known durable references. The same
  union resolves sibling reference sets (`turnReferenceSet`) for the
  shared-reference scan, the required-version scan (native legal-hold
  removal parity) and plan-backed coverage: a partially disposed sibling
  with a surviving admission fences the versions its truncated live
  enumeration no longer lists, and a rolled-back interrupted deletion's
  physically deleted-but-undispositioned identities keep fencing until a
  verified disposition records the loss. The production deletion loop
  continues after `ErrObjectProtected`, so a surviving admission with
  deleted subsequent event slots is a REACHABLE interrupted-disposal
  state (the round-4 drills interrupt the ACTUAL `FinishPurge` with
  selective native protection; the earlier rounds' admission-first
  synthetic deletions are only one shape among many).
- **A surviving admission with verifiably gone event-zero data is a
  reconcilable gap, never a tenant-wide wedge** (finding 2, HIGH):
  `InventoryTurnsWithGaps` separates admission gaps (the marker
  survives, the event-zero data version is verifiably absent) from hard
  identity failures (corrupt, ambiguous or transient - those still fail
  the inventory). A gap turn is omitted from the live inventory and
  reconciled against the durable disposal plan and lifecycle catalog,
  which must both exist and bind to the exact tenant, turn and project
  the surviving admission names; unplanned identity loss (no plan, no
  catalog binding) still fails closed. Plan-backed gap turns keep the
  full lifecycle operational - hold placement over the interrupted
  record reports `partially_disposed` with the storage-verified losses
  counted, hold placement over UNRELATED records is never blocked, and
  ordinary disposal resumes after release and retention expiry. A LIVE
  record with a durable disposal plan is covered the same way (from the
  plan, probing every outstanding version) - a truncated live
  enumeration is never silently passed as complete coverage. A 404 from
  any storage read is the canonical `ErrObjectAbsent`, so absence is
  verifiable wherever it is observed.
- **Release-cleanup reports converge to the committed ownership ledger**
  (finding 3, MEDIUM): the report is refreshed whenever there is
  anything to converge - outstanding claims to record, or a stale
  non-empty pending list to clear on verified clearance - from both
  release paths (including the idempotent retry) and from recovery,
  which refreshes ZERO-claim holds instead of skipping them. Repair-state
  publications verify the hold's lifecycle state atomically with the
  write: a hold released after recovery's listing never receives stale
  effective-hold repair results.

## Round-5 review corrections (the adversarial lanes over the round-4 fixes)

- **An unreadable disposal plan is an UNKNOWN version set** (lane 1): the
  plan read inside the shared-reference scan and the sibling reference
  resolution (`turnReferenceSet`) FAILS CLOSED - a plan-read error is never
  treated as "no plan exists". A SUCCEEDED live enumeration can be
  truncated, so ignoring the error would let the truncated result silently
  override durable references while an irreversible deletion or a native
  legal-hold removal proceeds; the operation is refused and the condition
  is retryable (converging once the plan read recovers).
- **Cleanup reports are published ATOMICALLY with the claims-ledger
  snapshot** (lanes 2 and 4): `RecordCleanupState` locks the hold row and
  the outstanding claim rows inside the single transaction that writes the
  report, so a concurrent release or recovery reconciliation can never
  leave a published cleanup list that the committed ledger has already
  superseded. Lock order (holds row, then claim rows) preserves the
  declared global order.
- **Repair-state writes bind to the owning tenant** (lane 4):
  `SetRepairState` resolves the locked hold by id, then verifies the
  supplied tenant and the scope revision before any write: a foreign
  tenant identifier never authorizes another tenant's report mutation or
  its audit attribution.

## Concurrency and recovery

- Placement, release and scope change serialize on the per-matter epoch row;
  disposal locks the tenant protection fence and the epoch row across its
  deletes (the conditional-delete fence). Interleavings A-G of the state
  machines are executable tests.
- Concurrent sweeps are idempotent (exactly-once marking); concurrent
  same-key placements create exactly one hold, one epoch and one audit row;
  overlapping releases are idempotent; concurrent purge finishes dispose
  exactly once; concurrent duplicate establishments write exactly one
  `hold.effective` audit row (idempotent completion writes none).
- Deterministic barriers (`records.Store.Hooks`, `records.Service.Hooks`)
  freeze a lifecycle transaction at its epoch lock, its protection fence or
  a storage delete so races are reproduced without sleeps.
- Recovery (`records.Service.Recover`, at serving start, no user
  authorization, no workspace tables): re-establishes pending/failed holds
  (uncovered records keep them from becoming effective), reconciles every
  hold's outstanding protection claims (cleanup converges for released and
  narrowed holds alike), completes interrupted conditional deletes from
  their durable disposal plans, and classifies presence so unknown
  observations never become disposal. The crash-window between a committed
  storage delete and the uncommitted transaction is recovered idempotently
  (absent versions complete the disposal from the plan); a hold landing in
  that window records `disposed_before_hold` - including turns that already
  left the live inventory (the durable catalog supplies the gap report).
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
