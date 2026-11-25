# Versioning the contracts

Applies to the event schema, export manifest, canonical hashing rules and the ordering rules R1-R4.

1. Every event and manifest carries `schema_version` (semver `MAJOR.MINOR.PATCH`). A log may contain several versions; each event is verified under *its own* version.
2. **MAJOR**: changes to canonicalization, hash algorithm, chain construction, ordering rules, or meaning/removal of an existing field. Old verifiers must reject it. Requires an ADR amendment and a migration note.
3. **MINOR**: new optional fields or new event types that do not alter existing hashes or rules. Unknown fields are preserved, hashed and ignored by older verifiers; unknown event *types* are accepted but cannot satisfy any gate.
4. **PATCH**: clarifications and fixtures; no behavior change.
5. **Stored events are never rewritten or re-hashed.** Migrations append new records (e.g. `outcome_resolved`) or produce new derived exports. Verifiers for every released MAJOR version stay in the repository.
6. **Golden fixtures** in `fixtures/contracts/` pin the hashes. A change that alters a golden hash is by definition a MAJOR change and must be called out in the pull request.
7. **Exact sent context is mandatory.** `context_sealed` and `disclosure_intent` reference the byte-exact provider request object (sha256 + length) and the exact source versions (`source_id`, `version`, `sha256`) that went into it. Implementations must not re-render a prompt from the workspace, a template or a newer document version when exporting; if the object is missing the verifier fails. Changing prompt templates, redaction or serialization therefore never changes historical evidence.
8. Contract changes ship with updated fixtures, tests, and a changelog line in this file.

## Changelog

- 1.0.0 (proposed): initial contract. Review fixes before freeze: R4 now requires an `allow` decision; canonicalization pinned to UTF-16 key order with cross-language vectors; purge specified as tombstone + conditional delete.
- 1.0.0 (proposed, #4): implementation adds only optional fields, no hash or rule change: `turn_received.payload.{request_id,input}`, `policy_decision.payload.destination`, `disclosure_intent.payload.model_id`, `provider_accepted.payload.model_id`, `evidence_ack.payload.storage_level`, and `deny` reasons. The Go verifier reproduces every golden fixture hash.
