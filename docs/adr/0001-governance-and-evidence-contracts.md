# ADR 0001: Governance and evidence contracts

- Status: Proposed (for review under issue #1)
- Scope: the pilot described in [docs/pilot.md](../pilot.md). Synthetic data only.
- Companion documents: [role matrix](../contracts/role-matrix.md), [state machines](../contracts/state-machines.md), [versioning](../contracts/versioning.md)
- Executable examples: `fixtures/contracts/` and `tests/contracts/`

> Nothing here is a claim of legal compliance, legal sufficiency, or eDiscovery
> readiness. These are technical contracts to be tested by the pilot drill.

## 1. Context and decision

Charter must enforce who may use which model and preserve the exact AI work done
on a held matter, even after the ordinary workspace view changes. We decide that:

1. The **workspace** (chats, projects, documents as users see them) is a mutable
   working copy. **Evidence** is a separate, append-only, restricted record.
   Evidence is never a second UI for reading work the reader could not otherwise see.
2. Every model turn is described by an **ordered, hash-chained event log**.
   Events are the only source of truth for what happened.
3. A turn may disclose data to a provider only after a **write-ahead
   disclosure intent** is durably acknowledged, and a response may be released to
   the client only after the **output is durably acknowledged**.
4. **Holds win over retention.** Disposal is two-phase and re-checks holds at the
   moment of irreversible deletion.
5. The **exact bytes sent** to the provider are stored. Context is never
   reconstructed afterwards from the workspace.

## 2. Trust boundaries

| Zone | Contains | Trusted for | Not trusted for |
| --- | --- | --- | --- |
| Client (browser/test harness) | UI, user input | Nothing; all input is untrusted | Identity, policy, model choice, credentials |
| Control plane (Charter service) | AuthN/Z, policy, routing, usage reservation, capture, hold, export | Enforcing policy; writing events | Availability of providers; its own durability without the evidence store ack |
| Evidence store | Append-only events and immutable objects | Durability, immutability, restricted read | Policy decisions |
| Workspace store | Mutable chats, projects, doc versions | Working copy only | Being a source of preservation |
| Model provider / adapter | Receives sent context, returns output | Nothing; assume disclosure is irreversible once bytes leave | Reporting its own outcome accurately |
| External source library (e.g. SharePoint, later) | Original documents | Origin of excerpts | Preservation (capturing an excerpt does not preserve the library) |
| Operators / infrastructure | Hosts, backups, keys | Keeping the system running | Reading content, changing holds or evidence |

Client-side model credentials are out of scope: the client never holds provider keys.

## 3. Identity and keys

All identifiers are opaque, immutable, lowercase UUIDs (or ULIDs) assigned by the
control plane. Display names are never keys.

| Key | Meaning |
| --- | --- |
| `tenant_id` | Customer-operated deployment boundary. Present on every record. |
| `project_id` | Isolation boundary within a tenant. Policy, membership and routing attach here. |
| `matter_id` | Legal/records grouping that holds attach to. A project maps to one or more matters; an event carries exactly one `matter_id` at capture time. |
| `custodian_id` | The user whose work is preserved (the actor on the turn). Survives account deactivation. |
| `turn_id` | One request/response exchange. |
| `seq` | 0-based position of an event within a turn. |
| `hold_id` | One hold. Holds are independent objects; evidence is *derived* held, never stamped. |

Evidence is addressed by `(tenant_id, project_id, turn_id, seq)` and objects by
`sha256`. Every query and storage path must include `tenant_id`; a request that
omits it or mismatches the caller's tenant is refused (negative-path test required
in #3). Moving a project between matters appends a new event; it never rewrites history.

## 4. Records and custodians

- A **record** is a turn's event log plus the objects the events reference
  (user input, sealed source excerpts, sent request bytes, output).
- A **custodian** is the `custodian_id` of the turn's actor. Revoking or deleting
  a user changes workspace access only; custodian attribution on existing
  evidence is permanent and holds scoped to that custodian continue to apply.
- Deleting a chat or project, or editing/deleting a source, creates workspace
  changes and does not alter evidence.

## 5. Event and export schema (v1)

Each event is a JSON object:

```json
{
  "schema_version": "1.0.0",
  "tenant_id": "...", "project_id": "...", "matter_id": "...",
  "turn_id": "...", "seq": 0,
  "type": "turn_received",
  "recorded_at": "2026-01-15T10:00:00.000Z",
  "actor": {"kind": "user|service", "id": "..."},
  "payload": { },
  "prev_hash": null,
  "event_hash": "sha256:<hex>"
}
```

Event types in v1: `turn_received`, `policy_decision`, `usage_reserved`,
`context_sealed`, `disclosure_intent`, `evidence_ack`, `provider_accepted`,
`output_recorded`, `response_released`, `usage_settled`, `turn_completed`,
`turn_interrupted`, `outcome_resolved`. Payload contracts are shown in
`fixtures/contracts/*.json`.

An **export bundle** is a directory containing `manifest.json` (schema version,
scope, creator, list of event logs with the head hash of each, list of objects
with `sha256` and byte length), the event logs (one JSON object per line), and
the objects named by their hash. A verifier needs only the bundle and this
document. Verification fails on any missing object, changed byte, broken chain,
or event-ordering rule violation (section 8).

## 6. Canonical hashing

- Algorithm: SHA-256, written `sha256:<64 lowercase hex>`.
- Event hash: SHA-256 of the canonical JSON of the event **without** `event_hash`.
- Canonical JSON: RFC 8785 (JCS) rules: UTF-8, object keys sorted **by UTF-16 code
  units** (not Unicode code points), no insignificant whitespace. The accepted
  format is deliberately constrained to what is portable: strings (no lone
  surrogates), booleans, null, arrays, objects, and **integers within
  +/-(2^53 - 1)**. Floating point numbers and larger integers are forbidden
  (use decimal strings or minor units); the reference model rejects them. Any
  implementation must reproduce `fixtures/contracts/canonical-vectors.json`
  byte for byte, including the UTF-16 ordering vector.
  Timestamps are RFC 3339 UTC strings with millisecond precision, `Z` suffix.
- Chain: `prev_hash` of event N is `event_hash` of event N-1; event 0 has `null`.
  The chain head hash identifies the turn log.
- Objects are hashed over their raw bytes and are immutable.
- Anchoring heads externally (transparency log, WORM replication) is an
  open gap for the pilot; the chain proves internal consistency, not that the
  whole log was not replaced by someone with write access to the store.

## 7. Hold, time and retention semantics

**Scope.** A hold has `matter_id` (required), optional `custodian_ids` (empty = all
custodians), and an optional time window `[window_start, window_end)` applied to
the evidence's `recorded_at` (`window_end` null = open-ended, so future work on the
matter is covered until release).

**Held is derived.** An evidence item is *held* iff at least one **active** hold
matches it. Releasing a hold removes only that hold's claim; the item stays held
while any other active hold matches (tested: overlapping holds).

**Ordering and time.** Hold placement and release are assigned a monotonically
increasing `hold_epoch` by the control plane inside one serialized transaction.
Decisions about disposal compare epochs, never wall clocks, so clock skew cannot
reorder a hold behind an expiry. Wall-clock `placed_at` is informational.

**Retention.** Each evidence item has `retention_expires_at`. Eligibility for
disposal requires `now >= retention_expires_at` **and** not held.

**Disposal is two-phase** (see state machines):
1. *Sweep* marks eligible items `disposal_pending` and records the `hold_epoch` it observed.
2. *Purge*, after the grace period, is itself two steps so that a re-check can never
   be separated from the delete:
   - `begin_purge` re-evaluates holds, **tombstones** the item (unreadable to
     everyone; bytes retained) and records the `hold_epoch` it observed.
   - `finish_purge` is the only step that deletes bytes and must be a **conditional
     delete**: it succeeds only if the matter's `hold_epoch` is still the observed
     value. On mismatch it never deletes blindly: if a hold now matches, the
     tombstone is lifted (`active`); otherwise purge restarts under the new epoch.
   - Linearization point: a hold is *acknowledged* only once its epoch is committed.
     Any purge whose conditional delete commits after that point observes the
     bumped epoch and fails. A hold acknowledged before the delete commits
     therefore always protects the item, including against an in-flight purge.
   - If the storage backend cannot offer an atomic conditional delete (or an
     equivalent fence such as a per-matter lock held by both paths), purge must
     not be enabled. Proving this on a real backend is deferred to #4/#7 and
     is a recorded gap until then.
   A hold placed after the byte delete committed cannot recover the item: the
   system records a `disposed_before_hold` gap in the hold's report so the
   miss is visible rather than silent.
3. Purge requires an approval by `records_officer` (not `tenant_admin` or `operator`).

Retention is a technical timer here, not a statement of any legal retention period.

## 8. Release rule and durable evidence acknowledgment

Define `ack(N)`: an `evidence_ack` event whose payload names `acked_seq` and
`acked_event_hash`, created only after the evidence store confirmed a durable write
of event N and all earlier events (storage receipt: fsync/replication level set by
deployment; the pilot must record the level actually tested).

Mandatory ordering rules, enforced by the control plane and checked by the verifier:

- **R1 (write-ahead disclosure):** no byte may be sent to a provider before
  `ack(disclosure_intent)`. The intent carries the sha256 and length of the exact
  request bytes (already stored as an object) and the provider/endpoint identity.
- **R2 (release gate):** `response_released` is allowed only after `ack(output_recorded)`
  for the output being released. A response that has not been durably
  recorded is not delivered, so no successful response escapes without evidence.
- **R3 (single terminal event):** every turn ends in exactly one of `turn_completed`
  or `turn_interrupted`. `response_released` may occur only in a turn that ends in
  `turn_completed`.
- **R4 (policy first):** an `allow` `policy_decision` must precede `context_sealed`,
  `disclosure_intent`, `provider_accepted` and `response_released`. A `deny` ends the
  turn with no disclosure; the verifier rejects any of those events after a deny.
- If the evidence store is unavailable at any gate the turn fails closed
  (nothing is sent or released) and the failure is returned to the client.
  Fail-closed after R1 may waste a reservation but never causes unrecorded disclosure.

Streaming: for the pilot the control plane buffers provider output and releases
only after `ack(output_recorded)`. Streaming to the client in segments is allowed
later only if each released segment is acknowledged first.

## 9. Crashes and mid-stream provider failures

Disclosure state is **derived from the log**, never stored separately:

| Log contents | Disclosure |
| --- | --- |
| No acked `disclosure_intent` | `none` (R1 makes sending impossible) |
| Acked intent, no `provider_accepted` | `unknown` (a send may have occurred) |
| `provider_accepted` present | `disclosed` |

- **Mid-stream provider failure:** the partial output is stored as an object, an
  `output_recorded` event with `complete: false` is acknowledged, and the turn ends
  in `turn_interrupted` (`reason: provider_stream_error`). Nothing is released.
  The user may be told "failed"; the evidence says "disclosed, output partial".
- **Crash:** on restart, recovery scans for non-terminal turns and appends
  `turn_interrupted` (`reason: crash_recovery`) with the derived disclosure state.
  The recovery actor is `service`, never the original user.
- **Unknown outcome:** treated as **disclosed** for policy reporting, holds, export,
  and billing (usage is settled at the reserved maximum, basis `reserved_max`). The
  system never silently retries on another provider. A later reconciliation
  (provider logs) appends `outcome_resolved`; history is never edited.

## 10. Roles

See [role matrix](../contracts/role-matrix.md). Summary: `tenant_admin`,
`project_member`, `records_officer`, `export_reviewer` and `operator` are disjoint
capability sets. No role may edit or delete evidence. Hold placement, export
approval and purge approval require different people from the requestor.

## 11. Failure, recovery, backup and restore

- Evidence store is the system of record for evidence; the workspace store may be
  restored independently and must never be used to repair evidence.
- Backups of evidence are encrypted, restricted like the primary, and subject to the
  same holds: **a backup copy must not be used to resurrect disposed evidence**, and
  disposal records which backup generations still hold a copy (gap if unmanaged).
- After a restore, run chain verification on every log and compare head hashes with
  the last exported manifests; a mismatch or missing tail blocks release until
  reviewed. Events lost after the last ack are by definition ones whose responses
  were not released (R2); lost-but-disclosed intents are surfaced by R1 order.
- Control-plane crash is safe by R1/R2; evidence-store outage fails closed;
  provider outage yields `turn_interrupted` with disclosure state.
- The pilot must test actual storage protection (immutability/permissions) and
  record any mocked boundary as a gap, not a pass.

## 12. Out of scope and assumptions

Out of scope: legal compliance claims, desktop packaging, arbitrary tools, provider
failover, client-side credentials, other document connectors, legal-platform ingestion,
preserving external libraries. Assumptions: single trusted clock source on the control
plane (informational only), customer operates infrastructure, synthetic data,
identity provider is a test IdP in the pilot, and evidence-store administrators are
a residual risk mitigated by the role matrix and anchoring (open gap, section 6).

## 13. Consequences and open questions

- Write-ahead plus buffering adds latency; accepted for the pilot.
- Open: anchoring of chain heads; storage receipt level; grace-period length;
  whether `disposed_before_hold` should be blocking for matters with pending
  preservation notices (needs policy owner decision).


## 14. Amendment A1 (clarifications from the C04 review; no change to hashes or rules R1-R4)

Review of the first implementation (#4) found places where the text left room for a weaker reading. These are **clarifications** (PATCH under [versioning](contracts/versioning.md)); no event type, hash input or ordering rule changes.

1. **`response_released` is authorization, not receipt.** It records that the control plane, holding a durable acknowledged output and a fresh authorization, committed to release that output. It does not record transport delivery or client receipt, and Charter never claims receipt. Between that record and the HTTP write the request can still end; the output is then withheld and stays deliverable by a delivery-only retry (idempotent replay), which is authorized again at that moment.
2. **Delivery is authorized last.** The authorization check and the cancellation/deadline check run immediately before output is handed to the transport, after every evidence write (release record, settlement, terminal event, retries). R2 (durable before release) is unchanged; this adds that no evidence write can sit between the last check and delivery.
3. **Crash and failure semantics by point** (each row is what the log shows and what recovery does; none re-dispatches):

   | Failure point | Log | Disclosure | Recovery / result |
   | --- | --- | --- | --- |
   | before admission commits | nothing | none | request fails; nothing to recover |
   | admitted, before acked intent | `turn_received`... | none | `turn_interrupted(crash_recovery)` |
   | cancelled/expired after acked intent, before dispatch | intent + ack | **unknown** (over-reports; nothing was sent) | `turn_interrupted(cancelled_before_dispatch)`, settled at reserved max |
   | after intent ack, before `provider_accepted` | intent + ack | unknown | `turn_interrupted(crash_recovery)` |
   | output acked, authorization refused | `output_recorded`+ack | disclosed | `turn_interrupted(release_denied)` |
   | `response_released` committed, settlement or terminal write lost | release recorded | disclosed | recovery appends `usage_settled` and `turn_completed` (R3: a released turn completes); output is deliverable by delivery-only retry |
   | terminal committed, transport delivery fails | `turn_completed` | disclosed | no log change; client retries with the same key |

4. **Single-instance recovery.** Recovery terminalizes every open turn older than the process start, so it must not run while another instance can be mid-turn. The pilot enforces one live control-plane instance with a PostgreSQL advisory-lock fence held on a dedicated connection for the life of the process; the process refuses to start without it. Multi-instance operation needs per-turn leases and is out of scope.
5. **Idempotency identity.** A key is scoped to (tenant, project, custodian) and bound to a deterministic fingerprint of tenant, project, matter, custodian, the exact input and the ordered source selection (ids, versions, hashes, lengths); request ids and timestamps are excluded. A repeat with a different fingerprint is refused. After an interrupted turn with disclosure `unknown` or `disclosed`, a new request is **not** presented as a safe retry: the outcome needs review (reconciliation via `outcome_resolved`).
6. **Verifier strictness** (sections 5-9, state-machines.md) is now executable in full: envelope and identifier syntax (`^[a-z0-9][a-z0-9._-]{0,127}$`, a superset of lowercase UUID/ULID that also admits the synthetic fixture ids), RFC 3339 millisecond `Z` timestamps, one `turn_received` at seq 0, exactly one `policy_decision` at seq 1 and nothing after a deny but the denied completion, the lifecycle transitions of state-machines.md, mandatory references (sealed objects, request hash and length matching the intent, sources among the sealed objects, a single output reference), a `turn_interrupted.disclosure` equal to the disclosure derived from the log, and object digests and byte lengths. Structural verification (log only) and full verification (log plus objects) are distinct. The legacy fixture form of `turn_received` with only `input_summary` is accepted so golden hashes do not change; events written by the recorder always carry an `input` reference. Strict parsing rejects duplicate keys, trailing data, invalid UTF-8 and lone surrogates instead of normalizing them.
