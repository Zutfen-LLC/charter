-- Identity, project membership, role separation and audit (C03, #3).
-- Identities are resolved from (tenant, validated subject) only. There is
-- deliberately NO email column: email is never an authentication key.
-- Every project-scoped row carries tenant_id and uses composite foreign keys so
-- a row cannot reference a project or user of another tenant.

CREATE TABLE tenants (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer        text NOT NULL,          -- exact OIDC issuer URL
    idp_tenant_id text NOT NULL,          -- tenant claim value (Entra "tid")
    name          text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, idp_tenant_id)
);

CREATE TABLE users (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    display_name text NOT NULL,
    disabled_at  timestamptz,             -- set = all access denied immediately
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);

-- Pre-provisioned only: an unknown (tenant, subject) is refused, never auto-created.
CREATE TABLE identities (
    tenant_id uuid NOT NULL,
    subject   text NOT NULL,
    user_id   uuid NOT NULL,
    PRIMARY KEY (tenant_id, subject),
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id)
);

-- Tenant-level capability roles (docs/contracts/role-matrix.md). Disjoint from
-- project membership: holding one grants no workspace read access.
CREATE TABLE tenant_roles (
    tenant_id  uuid NOT NULL,
    user_id    uuid NOT NULL,
    role       text NOT NULL CHECK (role IN ('tenant_admin','records_officer','export_reviewer','operator')),
    granted_by uuid,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id)
);

CREATE TABLE projects (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);

CREATE TABLE project_members (
    project_id uuid NOT NULL,
    tenant_id  uuid NOT NULL,
    user_id    uuid NOT NULL,
    added_by   uuid,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id),
    FOREIGN KEY (project_id, tenant_id) REFERENCES projects(id, tenant_id),
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id)
);
CREATE INDEX project_members_user ON project_members(user_id);

-- Minimal project-scoped workspace object used to exercise isolation until
-- real chats/documents arrive (#5/#6). Synthetic content only.
CREATE TABLE artifacts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL,
    project_id uuid NOT NULL,
    title      text NOT NULL,
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (project_id, tenant_id) REFERENCES projects(id, tenant_id)
);
CREATE INDEX artifacts_project ON artifacts(project_id);

-- Append-only audit trail of role/membership changes.
CREATE TABLE audit_log (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    tenant_id uuid NOT NULL,
    actor_id uuid,
    action   text NOT NULL,
    detail   jsonb NOT NULL DEFAULT '{}'
);
CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END $$;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
