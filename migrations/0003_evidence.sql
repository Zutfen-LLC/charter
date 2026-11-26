-- Evidence store (C04, #4). ADR 0001 sections 5-9.
--
-- Evidence is deliberately SEPARATE from the workspace/search tables
-- (artifacts, project_members, ...): nothing here is joined into, indexed by,
-- or readable through any workspace query. Rows are append-only and
-- content-addressed. There are NO foreign keys to workspace tables, so a
-- workspace change (deleting a project, a user, a chat) can never alter or
-- block evidence; identifiers are stored as opaque values.
--
-- Protection is layered and HONESTLY LIMITED: privileges (role
-- charter_evidence_app has INSERT/SELECT only) plus triggers that refuse
-- UPDATE/DELETE/TRUNCATE for everyone, including the table owner. A database
-- superuser or owner can still drop the triggers, so this is NOT retention-
-- enforced storage. See docs/evidence-capture.md.

-- A project maps to a matter at capture time (ADR 3). One matter per project in
-- the pilot; moving a project later appends a new event, never rewrites history.
ALTER TABLE projects ADD COLUMN matter_id uuid NOT NULL DEFAULT gen_random_uuid();

-- One row per turn: the admission record. Written in the same transaction as
-- event 0 (turn_received), before any outbound dispatch.
CREATE TABLE evidence_turns (
    turn_id         uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL,
    project_id      uuid NOT NULL,
    matter_id       uuid NOT NULL,
    custodian_id    uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    input_sha256    text NOT NULL CHECK (input_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    admitted_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (turn_id, tenant_id),
    UNIQUE (tenant_id, project_id, custodian_id, idempotency_key)
);

-- Hash-chained event log. body is the exact canonical JSON (RFC 8785 subset)
-- that was hashed, including event_hash; the columns are a query convenience.
CREATE TABLE evidence_events (
    turn_id    uuid NOT NULL,
    tenant_id  uuid NOT NULL,
    seq        integer NOT NULL CHECK (seq >= 0),
    type       text NOT NULL,
    prev_hash  text CHECK (prev_hash ~ '^sha256:[0-9a-f]{64}$'),
    event_hash text NOT NULL CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
    body       text NOT NULL,
    stored_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (turn_id, seq),
    UNIQUE (turn_id, event_hash),
    FOREIGN KEY (turn_id, tenant_id) REFERENCES evidence_turns(turn_id, tenant_id)
);
CREATE INDEX evidence_events_tenant ON evidence_events(tenant_id, turn_id);

-- Immutable content-addressed objects: exact submitted input, sealed source
-- excerpts, sent request bytes, output/artifact bytes.
CREATE TABLE evidence_objects (
    tenant_id  uuid NOT NULL,
    sha256     text NOT NULL CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$'),
    length     bigint NOT NULL,
    bytes      bytea NOT NULL,
    stored_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sha256),
    CHECK (length = octet_length(bytes))
);

-- The stored bytes must hash to the address they are stored under.
CREATE FUNCTION evidence_objects_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.sha256 <> 'sha256:' || encode(sha256(NEW.bytes), 'hex') THEN
        RAISE EXCEPTION 'evidence object does not match its sha256 address';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER evidence_objects_hash BEFORE INSERT ON evidence_objects
    FOR EACH ROW EXECUTE FUNCTION evidence_objects_check();

-- Chain enforcement, serialized per turn: event 0 has no prev; every later
-- event must be seq+1 with prev_hash = the previous event_hash; nothing may be
-- appended after a terminal event (ADR R3 single terminal event).
CREATE FUNCTION evidence_events_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_seq integer; last_hash text; last_type text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.turn_id::text, 4001));
    SELECT seq, event_hash, type INTO last_seq, last_hash, last_type
      FROM evidence_events WHERE turn_id = NEW.turn_id ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq <> 0 OR NEW.prev_hash IS NOT NULL THEN
            RAISE EXCEPTION 'evidence chain: first event must be seq 0 with no prev_hash';
        END IF;
    ELSE
        IF last_type IN ('turn_completed', 'turn_interrupted') THEN
            RAISE EXCEPTION 'evidence chain: turn is terminal';
        END IF;
        IF NEW.seq <> last_seq + 1 OR NEW.prev_hash IS DISTINCT FROM last_hash THEN
            RAISE EXCEPTION 'evidence chain: event does not extend the chain';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER evidence_events_chain BEFORE INSERT ON evidence_events
    FOR EACH ROW EXECUTE FUNCTION evidence_events_chain();

-- Append-only for everyone, owner included.
CREATE FUNCTION evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only evidence', TG_TABLE_NAME;
END $$;
CREATE TRIGGER evidence_turns_rowguard BEFORE UPDATE OR DELETE ON evidence_turns
    FOR EACH ROW EXECUTE FUNCTION evidence_immutable();
CREATE TRIGGER evidence_events_rowguard BEFORE UPDATE OR DELETE ON evidence_events
    FOR EACH ROW EXECUTE FUNCTION evidence_immutable();
CREATE TRIGGER evidence_objects_rowguard BEFORE UPDATE OR DELETE ON evidence_objects
    FOR EACH ROW EXECUTE FUNCTION evidence_immutable();
CREATE TRIGGER evidence_turns_truncate BEFORE TRUNCATE ON evidence_turns
    FOR EACH STATEMENT EXECUTE FUNCTION evidence_immutable();
CREATE TRIGGER evidence_events_truncate BEFORE TRUNCATE ON evidence_events
    FOR EACH STATEMENT EXECUTE FUNCTION evidence_immutable();
CREATE TRIGGER evidence_objects_truncate BEFORE TRUNCATE ON evidence_objects
    FOR EACH STATEMENT EXECUTE FUNCTION evidence_immutable();

-- The application evidence role: it can add and read evidence, nothing else.
-- Deployments GRANT it to the login role the control plane uses for evidence.
-- Roles are cluster-wide; creating one needs CREATEROLE, so a failure is
-- surfaced as a NOTICE and the qualification test fails rather than silently
-- passing.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'charter_evidence_app') THEN
        BEGIN
            CREATE ROLE charter_evidence_app NOLOGIN;
        EXCEPTION WHEN insufficient_privilege OR duplicate_object THEN
            RAISE NOTICE 'could not create role charter_evidence_app';
        END;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'charter_evidence_app') THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO charter_evidence_app', current_schema());
        REVOKE ALL ON evidence_turns, evidence_events, evidence_objects FROM PUBLIC;
        GRANT SELECT, INSERT ON evidence_turns, evidence_events, evidence_objects TO charter_evidence_app;
    END IF;
END $$;
