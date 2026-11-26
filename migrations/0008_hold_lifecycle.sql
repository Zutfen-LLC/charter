-- Hold, deletion and retention lifecycle (C07, #7). ADR 0001 section 7.
--
-- This is CONTROL-PLANE lifecycle state, not evidence: the append-only
-- evidence tables (0003) and retained storage namespaces are untouched, and
-- no row here is joined into or readable through any workspace query. The
-- catalog is derived from the AUTHORITATIVE evidence backend by the sweep
-- (never from workspace tables), so recovery works with workspace records
-- unavailable. Disposal decisions compare hold epochs, never wall clocks.

-- Tenant retention policy: how long ordinary (unheld) evidence stays
-- retention-eligible before it may be swept for disposal.
CREATE TABLE retention_policies (
    tenant_id         uuid PRIMARY KEY,
    retention_seconds bigint NOT NULL CHECK (retention_seconds >= 1),
    grace_seconds     bigint NOT NULL DEFAULT 604800 CHECK (grace_seconds >= 0),
    set_by            uuid,
    set_at            timestamptz NOT NULL DEFAULT now()
);

-- Monotonic per-matter hold epoch. Hold placement, release and scope change
-- take the next epoch inside the transaction that locks this row; the
-- disposal path locks the same row before any irreversible delete, which is
-- the conditional-delete fence of ADR 0001 section 7.
CREATE TABLE matter_hold_epochs (
    tenant_id uuid NOT NULL,
    matter_id uuid NOT NULL,
    epoch     bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, matter_id)
);

-- Holds. state:
--   pending   epoch committed (disposal is fenced) but storage-native
--             protection is not yet established and verified
--   effective protection established and read back
--   failed    protection establishment failed (retryable; the epoch fence
--             remains in force - a failed hold never silently weakens)
--   released  the claim is removed; only this hold's claim
CREATE TABLE holds (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    matter_id      uuid NOT NULL,
    reason         text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    window_start   timestamptz,
    window_end     timestamptz,
    state          text NOT NULL CHECK (state IN ('pending','effective','failed','released')),
    epoch          bigint NOT NULL CHECK (epoch >= 1),
    release_epoch  bigint,
    placed_by      uuid NOT NULL,
    placed_at      timestamptz NOT NULL DEFAULT now(),
    effective_at   timestamptz,
    released_by    uuid,
    released_at    timestamptz,
    release_reason text,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    report         jsonb NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, idempotency_key),
    CHECK (window_start IS NULL OR window_end IS NULL OR window_end > window_start)
);
CREATE INDEX holds_tenant_matter ON holds(tenant_id, matter_id);

-- Custodian scope; no rows = all custodians of the matter.
CREATE TABLE hold_custodians (
    hold_id      uuid NOT NULL REFERENCES holds(id) ON DELETE CASCADE,
    tenant_id    uuid NOT NULL,
    custodian_id uuid NOT NULL,
    PRIMARY KEY (hold_id, custodian_id)
);

-- Retention lifecycle catalog: one row per evidence turn (state machines doc
-- "Evidence item retention"). populated/refreshed by the sweep from the
-- authoritative backend; state transitions are the two-phase disposal of
-- ADR 0001 section 7 with hold-epoch interlocks.
CREATE TABLE retention_items (
    tenant_id            uuid NOT NULL,
    turn_id              uuid NOT NULL,
    matter_id            uuid NOT NULL,
    project_id           uuid NOT NULL,
    custodian_id         uuid NOT NULL,
    recorded_at          timestamptz NOT NULL,
    retention_expires_at timestamptz NOT NULL,
    state                text NOT NULL DEFAULT 'active'
                         CHECK (state IN ('active','disposal_pending','purging','disposed')),
    observed_epoch       bigint,
    pending_since        timestamptz,
    sweep_by             uuid,
    tombstoned_at        timestamptz,
    purge_by             uuid,
    purged_at            timestamptz,
    PRIMARY KEY (tenant_id, turn_id)
);
CREATE INDEX retention_items_matter ON retention_items(tenant_id, matter_id);

-- Grants follow the 0005 split: these are workspace-tier control tables, and
-- the serving process reaches them with the charter_workspace_app login.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'charter_workspace_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON retention_policies, matter_hold_epochs, holds, hold_custodians, retention_items TO charter_workspace_app');
    END IF;
END $$;
