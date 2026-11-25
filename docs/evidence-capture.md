# Evidence capture and the durable write path (C04, #4)

Implements the contract in [ADR 0001](adr/0001-governance-and-evidence-contracts.md) sections 5-9. Synthetic data only. **Nothing here is a claim of legal compliance or eDiscovery readiness.**

## What is recorded

For every model turn (`POST /v1/projects/{pid}/model-calls`) the recorder writes a hash-chained event log plus content-addressed objects:

| Requirement | Where it is recorded |
| --- | --- |
| tenant / project / matter / custodian | on every event (`tenant_id`, `project_id`, `matter_id`); custodian is `actor.id` of `turn_received` and the `evidence_turns` row |
| request id, turn id, time | `turn_received.payload.request_id`, `turn_id`, `recorded_at` (RFC 3339 ms `Z`) |
| policy decision and **actual** destination/model | `policy_decision` (`destination`) and `disclosure_intent` (`provider`, `endpoint_id`, `model_id`); never client-supplied |
| exact submitted input | object named by `turn_received.payload.input` |
| retrieved excerpts, source references and versions | excerpt bytes are objects; `context_sealed.payload.sources` = `source_id`, `version`, `sha256` |
| exact bytes sent | the request object named by `context_sealed.request_sha256` and `disclosure_intent.request`; the stored bytes **are** what the model received |
| output / artifact bytes and hashes | `output_recorded` object (`complete` true/false) |
| partial and failure outcomes | `output_recorded(complete=false)`, `usage_settled`, `turn_interrupted` (`reason`, derived `disclosure`) |

Workspace artifacts have no version history yet, so an artifact used as an excerpt is recorded as `version: 1` with its content hash; the hash is the authoritative identity until #6 adds real source versions.

## Separation from the workspace

Evidence lives in `evidence_turns`, `evidence_events` and `evidence_objects` (migration `0003`). They have **no foreign keys to workspace tables** and no workspace query reads or joins them, so the search index cannot surface evidence and deleting a project, user or artifact cannot alter or block evidence (tested). The role `charter_evidence_app` has `INSERT` and `SELECT` on the three tables and nothing on workspace tables. There is deliberately no evidence read API in this slice; reading and export arrive with #7/#8 and must apply their own authorization.

## Ordering, fail-closed and the release gate

`evidence.Recorder.Process` is the only write path:

1. **Admission** is committed (turn row, input object, `turn_received`) before policy or dispatch work. A repeated `Idempotency-Key` returns the existing turn.
2. `policy_decision`, `usage_reserved`, excerpts and request objects, `context_sealed`, `disclosure_intent` and its `evidence_ack` are durable before the model is called (**R1**).
3. The output (or partial output) object and `output_recorded` are durable and acknowledged before anything is released (**R2**). Output is buffered, not streamed.
4. The caller's release gate (the authorization re-check from #3) runs after the output ack and may veto; a veto records `turn_interrupted(release_denied)` and releases nothing.
5. `response_released`, `usage_settled`, `turn_completed`.

Any evidence write failure at any step fails closed: nothing is released (HTTP 503, no output) and the turn is marked interrupted, or left open for recovery if even that cannot be stored. `POST model-calls` with no recorder configured is refused before any model work.

The chain and the single-terminal rule are also enforced inside the database (trigger): out-of-order or wrongly chained events and anything after a terminal event are rejected, serialized per turn, so a live request and crash recovery cannot both end a turn.

## Crashes and replays

`charter serve` runs recovery before accepting requests. Every turn without a terminal event gets, as the `service` actor, `usage_settled` at the reserved maximum (if disclosure is not `none`) and `turn_interrupted(reason: crash_recovery, disclosure: <derived>)`. **Disclosure after an acknowledged intent with no `provider_accepted` is `unknown`** and is reported as such, never guessed away. A turn already logged as `response_released` is completed instead (R3). Recovery assumes a single control-plane instance (it resolves all open turns older than "now"); multi-instance deployment needs a lease and is out of scope for the pilot.

A retried request is never replayed to a model on uncertain dispatch:

| State of the turn for that key | Result |
| --- | --- |
| completed | `200`, stored output, `replayed: true`, no model call (still goes through the release gate; delivery is not logged as a second release) |
| in flight or awaiting recovery | `409` |
| interrupted (any disclosure) | `409`; the user must choose a new key. An explicit "safe retry" policy does not exist yet |
| denied | `403` |
| same key, different input | `422` |

## Storage receipts and hashes

Hashing is the canonical form of ADR 0001 section 6, implemented in Go and verified against `fixtures/contracts/` (the Python reference fixtures verify unchanged in Go, and tampering, dropped events, changed or missing objects and R1/R2 violations are rejected). Each durable write returns a receipt `{backend, level, id}`; `id` is a SHA-256 over the stored item and location, so replaying a write returns an identical receipt. The `evidence_ack` payload carries `receipt` and `storage_level` (an optional field; see versioning). For PostgreSQL the level is `postgres:fsync=on,synchronous_commit=on`: each evidence transaction forces `synchronous_commit=on` regardless of session defaults and refuses to write if the server runs with `fsync=off`. Replica or WAL-archive durability is not assessed.

Keeping secrets out: payload keys that look like credentials, headers or telemetry (`authorization`, `token`, `cookie`, `secret`, `password`, `api_key`, `header`, `user_agent`, `ip_address`, ...) are refused at write time, request headers are never read into evidence, and a test confirms a bearer token, forwarded address, user agent and cookie appear in no evidence row, object or log line. The user's own input and the excerpts are stored exactly as submitted, so they are the one place user-typed secrets can appear; that is inherent in "exact submitted inputs".

## Protection against application credentials, and the open gap

`evidence.QualifyProtection` attempts to rewrite and delete events, objects and turns and to truncate, as a given credential, in rolled-back transactions, and reports every attempt that was **not** refused. Against PostgreSQL:

- as `charter_evidence_app` (privileges): all refused, and the role cannot disable triggers, drop tables or grant itself more;
- as the table owner (triggers): all refused.

**Not met, and not claimed:** the table owner or a superuser can still disable the triggers (asserted by `TestPostgresBackendIsNotRetentionEnforced_RecordedGap`), so this backend reports `retention_enforced: false` and `/healthz` says so. The deployment must run the control plane as a login role that is a member of `charter_evidence_app` and is not the owner; the dev stack and tests use the owner. **"Prove against a genuine retention-capable test backend before pilot qualification" remains open:** it needs a WORM/object-lock backend implementing `evidence.Backend` and `evidence.Prober`, run through the same suite and the same fault-injection tests. Until then preservation is unqualified, and chain heads are not anchored externally (ADR section 6).

## Tests

`go test ./internal/evidence ./internal/server` (needs `CHARTER_TEST_DATABASE_URL`, see [local development](local-development.md)). Highlights: exact bytes and ordering at dispatch and at the release gate; denial, provider-error and partial-output logs verify; idempotent replay and key reuse; a crash after the intent ack; a fault injected at **every write** of a complete turn in three modes (rejected, committed-but-reported-failed, permanent outage), each followed by recovery, asserting nothing is released without evidence, a model call always implies disclosure is not `none`, the log is terminal and verifies, and the model is never dispatched twice.
