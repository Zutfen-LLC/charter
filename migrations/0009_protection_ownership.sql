-- Protection ownership, disposal plans and the tenant protection fence
-- (C07 review corrections, issue #7).
--
-- All three tables are additive control-plane state. They close three review
-- findings:
--
--   1. tenant_protection is the tenant-wide serialization point for every
--      native protection mutation (legal-hold set and clear), every disposal
--      delete and every capture-side reference acquisition. Removal and
--      establishment can no longer use incompatible snapshots: the clear
--      decision and the clear operation run under the same row lock as every
--      set, so a newer protection claim can never be overridden by a stale
--      cleanup (same-matter and cross-matter shared versions alike).
--
--   2. hold_version_claims is the durable protection ownership ledger. Every
--      path that establishes protection for a hold (initial establishment,
--      scope reestablishment, the recorder guard for future matching work)
--      records its exact version claims here BEFORE the storage mutation is
--      acknowledged, so release cleanup and crash recovery have a complete,
--      crash-safe derivation of what must be cleared - never only a
--      historical coverage report.
--
--   3. disposal_plans is the durable exact-version disposal plan, committed
--      before any irreversible deletion: interrupted deletions resume from
--      the plan without requiring already-deleted enumeration metadata, and
--      every planned version receives a verified disposition.

-- Tenant-wide protection fence: one row per tenant, lazily created. Locked
-- FOR UPDATE by establish/cleanup/deletion and by capture reference
-- acquisition. The epoch counter is advisory attribution for audit rows; the
-- lock itself is the fence. Global lock order is
--   tenants -> tenant_protection -> retention_items -> matter_hold_epochs
-- and every path acquires in that order only, so no new deadlock is
-- possible.
CREATE TABLE tenant_protection (
    tenant_id        uuid PRIMARY KEY,
    protection_epoch bigint NOT NULL DEFAULT 0,
    fenced_at        timestamptz NOT NULL DEFAULT now()
);

-- Durable protection ownership: one row per exact version a hold's
-- establishment caused to be protected. state:
--   pending    protection intent recorded; storage set/readback not yet verified
--   protected  native legal hold verified ON for this exact version
--   releasing  clear intent recorded (crash window); retry idempotent
-- Rows are deleted only after the legal hold is verified OFF and no longer
-- required; the audit trail keeps the attributable history.
CREATE TABLE hold_version_claims (
    tenant_id   uuid NOT NULL,
    hold_id     uuid NOT NULL REFERENCES holds(id) ON DELETE CASCADE,
    key         text NOT NULL,
    version     text NOT NULL,
    state       text NOT NULL CHECK (state IN ('pending','protected','releasing')),
    claimed_at  timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,
    PRIMARY KEY (hold_id, key, version)
);
CREATE INDEX hold_version_claims_hold ON hold_version_claims(tenant_id, hold_id, state);

-- Durable disposal plan: the exact version set authorized for deletion,
-- committed by begin_purge (before any irreversible delete). disposition:
--   planned          not yet attempted
--   deleted          storage confirmed the delete
--   absent           version was already gone (idempotent completion)
--   retained_shared  kept: another non-disposed record references it
--   protected        storage refused: retention or legal hold active
CREATE TABLE disposal_plans (
    tenant_id   uuid NOT NULL,
    turn_id     uuid NOT NULL,
    key         text NOT NULL,
    version     text NOT NULL,
    disposition text NOT NULL DEFAULT 'planned'
                 CHECK (disposition IN ('planned','deleted','absent','retained_shared','protected')),
    planned_at  timestamptz NOT NULL DEFAULT now(),
    plan_epoch  bigint,
    PRIMARY KEY (turn_id, key, version)
);
CREATE INDEX disposal_plans_turn ON disposal_plans(tenant_id, turn_id, disposition);

-- Grants follow the 0005/0008 split: workspace-tier control tables reached
-- with the charter_workspace_app login.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'charter_workspace_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_protection, hold_version_claims, disposal_plans TO charter_workspace_app');
    END IF;
END $$;
