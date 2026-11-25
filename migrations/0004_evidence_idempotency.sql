-- Evidence hardening (C04 review round).
--
-- Idempotency identity: a deterministic fingerprint over tenant, project,
-- custodian, matter, the exact input and the ordered source selection (ids,
-- versions, hashes, lengths). Volatile request ids and timestamps are excluded.
-- Rows written before this column existed carry '' and never match a replay
-- (fail closed: they are refused, not silently accepted).
ALTER TABLE evidence_turns
    ADD COLUMN request_fingerprint text NOT NULL DEFAULT ''
    CHECK (request_fingerprint = '' OR request_fingerprint ~ '^sha256:[0-9a-f]{64}$');
