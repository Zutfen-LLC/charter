# Evidence capture and the durable write path (C04, #4)

Implements the contract in [ADR 0001](adr/0001-governance-and-evidence-contracts.md) sections 5-9. Synthetic data only. **Nothing here is a claim of legal compliance or eDiscovery readiness.**

## What is recorded

For every model turn (`POST /v1/projects/{pid}/model-calls`) the recorder writes a hash-chained event log plus content-addressed objects:

| Requirement | Where it is recorded |
| --- | --- |
| tenant / project / matter / custodian | on every event (`tenant_id`, `project_id`, `matter_id`); custodian is `actor.id` of `turn_received` and the `evidence_turns` row |
| request id, turn id, time | `turn_received.payload.request_id`, `turn_id`, `recorded_at` (RFC 3339 ms `Z`) |
| policy decision and **actual** destination/model | `policy_decision` (`destination`), `disclosure_intent`, and `provider_accepted` (`provider`, `endpoint_id`, `model_id`); never client-supplied |
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
2. `policy_decision`, `usage_reserved`, excerpts and request objects, `context_sealed`, `disclosure_intent` and its `evidence_ack` are durable before the model is called (**R1**). If the request is cancelled or its deadline passes at any point before dispatch, including after the intent ack, **no model call is made**; the turn is closed `turn_interrupted(cancelled_before_dispatch)`.
3. The output (or partial output) object and `output_recorded` are durable and acknowledged before anything is released (**R2**). Output is buffered, not streamed.
4. The caller's gate runs after the output ack and may veto; a veto records `turn_interrupted(release_denied)` and releases nothing.
5. `response_released`, `usage_settled`, `turn_completed` are written.
6. **The gate runs again, last**: after every evidence write and retry, immediately before the output is handed to the transport, it re-reads authorization (active account AND project membership, on its own bounded context) and re-checks cancellation and the deadline. If it refuses, the response carries no output (403/503/504) even though the log says the release was authorized and the turn completed; a delivery-only retry with the same key is authorized afresh. This keeps C03's guarantee: output is never returned once the work context is known to be done or access is known to be revoked.

`response_released` means *authorized and committed to release*; it is not transport delivery or client receipt, and nothing here claims receipt (ADR 0001 amendment A1).

Any evidence write failure at any step fails closed: nothing is released (HTTP 503, no output) and the turn is marked interrupted, or left open for recovery if even that cannot be stored. `POST model-calls` with no recorder configured is refused before any model work. Evidence writes use a context detached from the request's cancellation (with their own timeout) so a cancelled request still records what it already did.

The chain and the single-terminal rule are also enforced inside the database (trigger): out-of-order or wrongly chained events and anything after a terminal event are rejected, serialized per turn, so a live request and crash recovery cannot both end a turn.

## Crashes, recovery and replays

`charter serve` acquires both [ownership and drain locks](fence-ownership.md) and recovers before accepting requests. Every unfinished turn is reconciled against its durable sequence. Denial completes as `denied` with zero disclosure, and a recorded `response_released` settles and completes instead of interrupting (R3). Other unfinished turns are interrupted as the service actor. An acknowledged intent without durably recorded provider acceptance leaves disclosure `unknown`, including when the adapter returned partial bytes; those bytes are preserved when their evidence write succeeds, never released, and usage is settled at the reserved maximum. Recovery does not call a model. Ambiguous commits are resolved by reloading the log, and retries cannot produce a second terminal event.

A retried request is never replayed to a model on uncertain dispatch. Identity of a repeated key is the **fingerprint** of tenant, project, matter, custodian, exact input and the ordered sources (ids, versions, hashes, lengths); request ids and timestamps are excluded.

| State of the turn for that key | Result |
| --- | --- |
| completed | `200`, stored output, `replayed: true`, no model call; the stored log must verify, belong to this request, and the output object must match its recorded hash and length, otherwise `503` and no output. The delivery gate still applies |
| in flight or awaiting recovery | `409` |
| interrupted, disclosure `none` | `409`; nothing was disclosed, so a new request may be submitted |
| interrupted, disclosure `unknown` or `disclosed` | `409`; **do not resubmit blindly**, the outcome needs review (a new key could disclose again) |
| denied | `403` |
| same key, different request (input, sources, versions, content, order or matter) | `422` |

## Storage receipts and hashes

Hashing is the canonical form of ADR 0001 section 6, implemented in Go and verified against `fixtures/contracts/` (the Python reference fixtures verify unchanged in Go, and tampering, dropped events, changed or missing objects and R1/R2 violations are rejected). Each durable write returns a receipt `{backend, level, id}`; `id` is a SHA-256 over the stored item and location, so replaying a write returns an identical receipt. The `evidence_ack` payload carries `receipt` and `storage_level` (required in the [current profile](verifier-profiles.md), optional for legacy fixtures). For PostgreSQL the level is `postgres:fsync=on,synchronous_commit=on`: each evidence transaction forces `synchronous_commit=on` regardless of session defaults and refuses to write if the server runs with `fsync=off`. Replica or WAL-archive durability is not assessed.

Keeping secrets out: payload keys that look like credentials, headers or telemetry (`authorization`, `token`, `cookie`, `secret`, `password`, `api_key`, `header`, `user_agent`, `ip_address`, ...) are refused at write time, request headers are never read into evidence, and a test confirms a bearer token, forwarded address, user agent and cookie appear in no evidence row, object or log line. The user's own input and the excerpts are stored exactly as submitted, so they are the one place user-typed secrets can appear; that is inherent in "exact submitted inputs".

## Runtime credentials

Migrations run as the schema **owner** (`charter migrate`, bootstrap only). The server serves with two different least-privilege logins and never holds the owner credential:

| Login | Member of | Can | Cannot |
| --- | --- | --- | --- |
| workspace (`CHARTER_DATABASE_URL`) | `charter_workspace_app` | read/write workspace tables, read `schema_migrations` | touch any evidence table at all |
| evidence (`CHARTER_EVIDENCE_DATABASE_URL`) | `charter_evidence_app` | INSERT and SELECT evidence tables | UPDATE/DELETE/TRUNCATE, disable triggers, drop, grant, create objects, read workspace tables, assume the owner |

`charter serve` **refuses to start** with migration credentials or an unsafe runtime profile. It verifies both the authenticated and active roles, the restricted role topology, and the effective table, column, schema and database permissions. See the [runtime credential policy](runtime-protection.md). Apply migrations with `charter migrate` and provision the distinct runtime logins with `scripts/dev.sh up` (dev) or `scripts/provision-runtime-roles.sql`. The serving process does not migrate.

## Protection qualification and the open gap

`evidence.QualifyProtection` reports **REFUSED**, **ALLOWED** or **INCONCLUSIVE** for each attempted operation. Preflight binds the expected runtime identity to an admin-verified database, schema, relation and seeded target, and verifies a positive control on a scratch table. Every operation is rolled back. Failed preflight, unrelated SQL errors, timeouts, failed transaction stages and absent targets cannot be counted as refusals. A self-grant must execute a valid `GRANT` against the bound target and either fail with `insufficient_privilege` or complete (PostgreSQL can issue a warning without changing the ACL). Readback verifies the actual privileges; failed savepoint or transaction completion is inconclusive. A report qualifies only with one refusal for each of the 12 checks, including schema drop and forbidden indirect authority. A `SET ROLE` run is inconclusive for role-assumption checks; only real login credentials can qualify. These are tests of the scoped PostgreSQL credential boundary, not of storage retention.

Against PostgreSQL:

- the evidence and workspace serving logins: all attacks REFUSED, qualified;
- the table owner: update/delete/truncate refused by the triggers, but it can disable them and drop the table (asserted by `TestOwnerCredentialIsNotQualified_RecordedGap`).

**Not met, and not claimed:** an owner or superuser can still disable the triggers, so this backend reports `retention_enforced: false` and `/healthz` says so. **Issue #4 stays open:** "prove against a genuine retention-capable test backend" needs a WORM/object-lock backend implementing `evidence.Backend` and `evidence.Prober`, run through the same qualification and fault-injection suites. Until then preservation is unqualified, and chain heads are not anchored externally (ADR section 6).

## Tests

`go test ./internal/evidence ./internal/server` (needs `CHARTER_TEST_DATABASE_URL`, see [local development](local-development.md)). Highlights: exact bytes and ordering at dispatch and at **both** release gates; cancellation, deadline, revocation, disabled account and authorization-database outage at each finalization write; no dispatch after cancellation; the shared negative verifier fixtures; qualification controls; the real restricted logins; overlapping recovery and the instance fence; denial, provider-error and partial-output logs verify; idempotent replay and key reuse; a crash after the intent ack; faults injected at **every reachable write** across successful turns and the denial, policy failure, provider error, partial output, veto, and cancellation paths in three modes (rejected, committed-but-reported-failed, persistent outage), each followed by recovery, asserting nothing is released without evidence, a model call always implies disclosure is not `none`, the log is terminal and verifies, and the model is never dispatched twice.
