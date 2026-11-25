-- Create the two serving LOGIN roles (idempotent). Run as a database
-- administrator AFTER `charter migrate`, which creates the NOLOGIN roles they
-- join. Usage:
--   psql -v ws_user=charter_ws -v ws_password=... -v ev_user=charter_ev -v ev_password=... \
--        -f scripts/provision-runtime-roles.sql
-- The two logins must be different, must not be superusers and must not own
-- the schema; the server refuses to start otherwise. Use real secrets in any
-- shared environment; the dev stack uses throwaway ones.
\set ON_ERROR_STOP on
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'ws_user', :'ws_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'ws_user') \gexec
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'ev_user', :'ev_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'ev_user') \gexec
SELECT format('GRANT charter_workspace_app TO %I', :'ws_user') \gexec
SELECT format('GRANT charter_evidence_app TO %I', :'ev_user') \gexec
