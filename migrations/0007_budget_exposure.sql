-- Record unquantifiable exposure without manufacturing a charge; retain
-- tenant-scoped incidents so a later project policy cannot bypass a freeze.
ALTER TABLE evidence_budget_reservations
 ADD COLUMN unquantified_exposure boolean NOT NULL DEFAULT false,
 ADD COLUMN tenant_frozen boolean NOT NULL DEFAULT false;
CREATE INDEX evidence_budget_tenant_frozen_idx ON evidence_budget_reservations(tenant_id) WHERE tenant_frozen;

CREATE OR REPLACE FUNCTION evidence_budget_set_policy(t uuid,p uuid,l boolean,a text[],pc bigint,tc bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM projects WHERE tenant_id=t AND id=p) THEN RAISE EXCEPTION 'invalid policy scope'; END IF;
 IF pc IS NULL OR pc<1 OR pc>9007199254740991 OR (tc IS NOT NULL AND (tc<1 OR tc>9007199254740991)) OR array_position(a,NULL) IS NOT NULL THEN RAISE EXCEPTION 'invalid budget policy'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(t::text,0));
 INSERT INTO evidence_budget_policy(tenant_id,project_id,local_only,allowed_models,project_cap,tenant_cap,enabled,frozen)
 VALUES(t,p,l,a,pc,tc,true,EXISTS (SELECT 1 FROM evidence_budget_reservations WHERE tenant_id=t AND tenant_frozen)) ON CONFLICT(tenant_id,project_id) DO UPDATE SET local_only=excluded.local_only,allowed_models=excluded.allowed_models,project_cap=excluded.project_cap,tenant_cap=excluded.tenant_cap,enabled=true;
END $$;

CREATE OR REPLACE FUNCTION evidence_budget_note_overrun(r uuid,amount bigint) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE x evidence_budget_reservations%ROWTYPE; tenant uuid; freeze_tenant boolean;
BEGIN
 SELECT tenant_id INTO tenant FROM evidence_budget_reservations WHERE reservation_id=r;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO x FROM evidence_budget_reservations WHERE reservation_id=r FOR UPDATE;
 IF NOT FOUND OR x.status<>'open' OR NOT x.dispatch_possible OR (amount IS NOT NULL AND (amount<=x.reserved_amount OR amount>9007199254740991)) THEN RETURN false; END IF;
 SELECT EXISTS (SELECT 1 FROM evidence_budget_policy q WHERE q.tenant_id=x.tenant_id AND q.tenant_cap IS NOT NULL) INTO freeze_tenant;
 UPDATE evidence_budget_reservations SET overrun=(overrun OR amount IS NOT NULL),
   overrun_floor=GREATEST(overrun_floor,amount), unquantified_exposure=(unquantified_exposure OR amount IS NULL),
   tenant_frozen=(tenant_frozen OR freeze_tenant) WHERE reservation_id=r;
 UPDATE evidence_budget_policy SET frozen=true WHERE tenant_id=x.tenant_id AND (project_id=x.project_id OR freeze_tenant);
 RETURN true;
END $$;

CREATE OR REPLACE FUNCTION evidence_budget_settle(r uuid,exact_amount bigint,is_unknown boolean) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE x evidence_budget_reservations%ROWTYPE; amount bigint; tenant uuid; BEGIN
 SELECT tenant_id INTO tenant FROM evidence_budget_reservations WHERE reservation_id=r;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO x FROM evidence_budget_reservations WHERE reservation_id=r FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 IF x.status='settled' THEN RETURN x.unknown=is_unknown AND x.actual_amount IS NOT DISTINCT FROM (CASE WHEN is_unknown THEN GREATEST(x.reserved_amount,x.overrun_floor) ELSE exact_amount END); END IF;
 IF x.status<>'open' OR NOT x.dispatch_possible OR (is_unknown AND exact_amount IS NOT NULL) OR (NOT is_unknown AND (exact_amount IS NULL OR exact_amount<0 OR exact_amount>9007199254740991)) THEN RETURN false; END IF;
 IF NOT is_unknown AND (x.unquantified_exposure OR exact_amount<x.overrun_floor) THEN RETURN false; END IF;
 amount:=CASE WHEN is_unknown THEN GREATEST(x.reserved_amount,x.overrun_floor) ELSE exact_amount END;
 UPDATE evidence_budget_reservations SET status='settled',actual_amount=amount,unknown=is_unknown,overrun=(amount>reserved_amount),settled_at=clock_timestamp() WHERE reservation_id=r;
 IF amount>x.reserved_amount AND x.overrun_floor<amount THEN
   -- Old exact evidence can still settle after upgrade. Use the same
   -- scope rule as the incident transition, including future policies.
   UPDATE evidence_budget_reservations SET tenant_frozen=true WHERE reservation_id=r AND
     EXISTS (SELECT 1 FROM evidence_budget_policy q WHERE q.tenant_id=x.tenant_id AND q.tenant_cap IS NOT NULL);
   UPDATE evidence_budget_policy SET frozen=true WHERE tenant_id=x.tenant_id AND (project_id=x.project_id OR EXISTS (SELECT 1 FROM evidence_budget_policy q WHERE q.tenant_id=x.tenant_id AND q.tenant_cap IS NOT NULL));
 END IF;
 RETURN true;
END $$;

-- Reassert the restricted search paths after replacement; grants carry over.
DO $$ DECLARE fn record;
BEGIN
 FOR fn IN SELECT p.oid::regprocedure AS sig FROM pg_proc p
   WHERE p.pronamespace=current_schema()::regnamespace AND p.proname IN
   ('evidence_budget_set_policy','evidence_budget_note_overrun','evidence_budget_settle') LOOP
   EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog,%I,pg_temp',fn.sig,current_schema());
 END LOOP;
END $$;
