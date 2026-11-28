-- C08 scoped evidence export authority and bounded package lifecycle.
CREATE TABLE scoped_exports (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 request_key text NOT NULL CHECK(length(request_key) BETWEEN 1 AND 128),
 project_id uuid NOT NULL,
 matter_id uuid NOT NULL,
 requester_id uuid NOT NULL,
 request_bytes bytea NOT NULL CHECK(octet_length(request_bytes) BETWEEN 1 AND 8192),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 custodian_ids uuid[] NOT NULL DEFAULT '{}',
 window_start timestamptz NOT NULL,
 window_end timestamptz NOT NULL CHECK(window_end>window_start),
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 2000),
 snapshot_bytes bytea NOT NULL CHECK(octet_length(snapshot_bytes)<=1048576),
 snapshot_digest text NOT NULL CHECK(snapshot_digest ~ '^[0-9a-f]{64}$'),
 manifest_digest text CHECK(manifest_digest IS NULL OR manifest_digest ~ '^[0-9a-f]{64}$'),
 requester_role text NOT NULL CHECK(requester_role='records_officer'),
 requester_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 requester_grant_at timestamptz NOT NULL,
 approver_id uuid,
 approver_role text CHECK(approver_role IS NULL OR approver_role='export_reviewer'),
 approved_at timestamptz,
 approver_grant_at timestamptz,
 state text NOT NULL CHECK(state IN ('requested','approved','generating','ready','failed','cancelled','expired')),
 attempt_token uuid,
 lease_until timestamptz,
 package_bytes bytea CHECK(package_bytes IS NULL OR octet_length(package_bytes)<=33554432),
 expires_at timestamptz DEFAULT (now()+interval '24 hours'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,requester_id,request_key),
 FOREIGN KEY(requester_id,tenant_id) REFERENCES users(id,tenant_id),
 FOREIGN KEY(approver_id,tenant_id) REFERENCES users(id,tenant_id),
 CHECK(approver_id IS NULL OR approver_id<>requester_id),
 CHECK((state='ready')=(package_bytes IS NOT NULL)),
 CHECK((state='generating')=(attempt_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((approver_id IS NULL AND approver_role IS NULL AND approved_at IS NULL AND approver_grant_at IS NULL) OR
       (approver_id IS NOT NULL AND approver_role IS NOT NULL AND approved_at IS NOT NULL AND approver_grant_at IS NOT NULL)),
 CHECK(state NOT IN ('approved','generating','ready','failed') OR approver_id IS NOT NULL),
 CHECK(state NOT IN ('requested','approved','generating','ready') OR expires_at IS NOT NULL),
 CHECK(state<>'ready' OR (approved_at IS NOT NULL AND approver_id IS NOT NULL AND expires_at IS NOT NULL AND manifest_digest IS NOT NULL))
);
CREATE INDEX scoped_exports_tenant_state ON scoped_exports(tenant_id,state,created_at);
CREATE FUNCTION scoped_exports_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'scoped export metadata is retained'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (NEW.id,NEW.tenant_id,NEW.request_key,NEW.project_id,NEW.matter_id,NEW.requester_id,NEW.request_bytes,NEW.request_digest,NEW.custodian_ids,NEW.window_start,NEW.window_end,NEW.reason,NEW.snapshot_bytes,NEW.snapshot_digest,NEW.requester_role,NEW.requester_at,NEW.requester_grant_at)
   IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.request_key,OLD.project_id,OLD.matter_id,OLD.requester_id,OLD.request_bytes,OLD.request_digest,OLD.custodian_ids,OLD.window_start,OLD.window_end,OLD.reason,OLD.snapshot_bytes,OLD.snapshot_digest,OLD.requester_role,OLD.requester_at,OLD.requester_grant_at)
  THEN RAISE EXCEPTION 'scoped export intent and snapshot are immutable'; END IF;
  IF OLD.approver_id IS NOT NULL AND (NEW.approver_id,NEW.approver_role,NEW.approved_at,NEW.approver_grant_at)
    IS DISTINCT FROM (OLD.approver_id,OLD.approver_role,OLD.approved_at,OLD.approver_grant_at) THEN RAISE EXCEPTION 'scoped export approval is immutable'; END IF;
  IF OLD.state='ready' AND NEW.state='ready' AND (NEW.package_bytes IS DISTINCT FROM OLD.package_bytes OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest) THEN RAISE EXCEPTION 'ready export package is immutable'; END IF;
  IF OLD.state='ready' AND NEW.state IN ('expired','cancelled') AND NEW.package_bytes IS NOT NULL THEN RAISE EXCEPTION 'terminal export retains no package bytes'; END IF;
  IF NOT ((OLD.state='requested' AND NEW.state IN ('approved','cancelled','expired')) OR (OLD.state='approved' AND NEW.state IN ('generating','cancelled','expired')) OR (OLD.state='generating' AND NEW.state IN ('generating','ready','failed','cancelled','expired','approved')) OR (OLD.state='ready' AND NEW.state IN ('ready','expired','cancelled')) OR (OLD.state IN ('failed','cancelled','expired') AND NEW.state=OLD.state)) THEN RAISE EXCEPTION 'invalid scoped export transition'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER scoped_exports_guard BEFORE UPDATE OR DELETE ON scoped_exports FOR EACH ROW EXECUTE FUNCTION scoped_exports_guard();
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='charter_workspace_app') THEN
  GRANT SELECT,INSERT,UPDATE ON scoped_exports TO charter_workspace_app;
 END IF;
END $$;
