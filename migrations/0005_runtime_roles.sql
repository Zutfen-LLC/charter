-- Least-privilege runtime roles (C04 review round).
--
-- The control plane must not serve with the credential that owns the schema.
-- Migrations run as the schema owner (`charter migrate`, bootstrap only). The
-- serving process uses TWO login roles that are members of these NOLOGIN roles:
--
--   charter_workspace_app  workspace tables only; NO privilege on evidence tables
--   charter_evidence_app   evidence tables only (INSERT, SELECT), see 0003
--
-- Neither can update/delete/truncate evidence, disable the guards, or assume the
-- owner role. Deployments create the login roles (scripts/provision-runtime-roles.sql)
-- and the server refuses to start if a credential is unsafe (owner, superuser,
-- CREATEROLE, member of the owner role, or holding any extra privilege).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'charter_workspace_app') THEN
        BEGIN
            CREATE ROLE charter_workspace_app NOLOGIN;
        EXCEPTION WHEN insufficient_privilege OR duplicate_object THEN
            RAISE NOTICE 'could not create role charter_workspace_app';
        END;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'charter_workspace_app') THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO charter_workspace_app', current_schema());
        REVOKE ALL ON tenants, users, identities, tenant_roles, projects, project_members, artifacts,
                      audit_log, instance, schema_migrations FROM PUBLIC;
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, users, identities, tenant_roles, projects,
                      project_members, artifacts TO charter_workspace_app;
        GRANT SELECT ON instance, schema_migrations TO charter_workspace_app;
        GRANT SELECT, INSERT ON audit_log TO charter_workspace_app;
        GRANT USAGE ON SEQUENCE audit_log_id_seq TO charter_workspace_app;
    END IF;
END $$;
