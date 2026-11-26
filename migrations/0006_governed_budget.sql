-- Server-owned governed inference budgets and routing policy.
CREATE TABLE evidence_budget_policy (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, local_only boolean NOT NULL,
 allowed_models text[] NOT NULL, project_cap bigint NOT NULL CHECK(project_cap BETWEEN 1 AND 9007199254740991),
 tenant_cap bigint CHECK(tenant_cap BETWEEN 1 AND 9007199254740991), enabled boolean NOT NULL DEFAULT true,
 frozen boolean NOT NULL DEFAULT false, PRIMARY KEY(tenant_id,project_id),
 CHECK(array_position(allowed_models,NULL) IS NULL)
);
CREATE TABLE evidence_budget_reservations (
 reservation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 turn_id uuid NOT NULL, idempotency_key text NOT NULL, model_id text NOT NULL, provider text NOT NULL,
 endpoint_id text NOT NULL, destination_model_id text NOT NULL,
 reserved_amount bigint NOT NULL CHECK(reserved_amount BETWEEN 0 AND 9007199254740991),
 period_start timestamptz NOT NULL, dispatch_possible boolean NOT NULL DEFAULT false,
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','released','settled')),
 actual_amount bigint CHECK(actual_amount BETWEEN 0 AND 9007199254740991), unknown boolean NOT NULL DEFAULT false,
 overrun boolean NOT NULL DEFAULT false, overrun_floor bigint NOT NULL DEFAULT 0 CHECK(overrun_floor BETWEEN 0 AND 9007199254740991), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), settled_at timestamptz,
 UNIQUE(tenant_id,project_id,idempotency_key), UNIQUE(tenant_id,turn_id)
);
CREATE INDEX evidence_budget_open_idx ON evidence_budget_reservations(status,period_start) WHERE status='open';
CREATE INDEX evidence_budget_scope_idx ON evidence_budget_reservations(tenant_id,project_id,period_start);
REVOKE ALL ON evidence_budget_policy,evidence_budget_reservations FROM PUBLIC;

CREATE FUNCTION evidence_budget_set_policy(t uuid,p uuid,l boolean,a text[],pc bigint,tc bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM projects WHERE tenant_id=t AND id=p) THEN RAISE EXCEPTION 'invalid policy scope'; END IF;
 IF pc IS NULL OR pc<1 OR pc>9007199254740991 OR (tc IS NOT NULL AND (tc<1 OR tc>9007199254740991)) OR array_position(a,NULL) IS NOT NULL THEN RAISE EXCEPTION 'invalid budget policy'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(t::text,0));
 INSERT INTO evidence_budget_policy(tenant_id,project_id,local_only,allowed_models,project_cap,tenant_cap,enabled,frozen)
 VALUES(t,p,l,a,pc,tc,true,false) ON CONFLICT(tenant_id,project_id) DO UPDATE SET local_only=excluded.local_only,allowed_models=excluded.allowed_models,project_cap=excluded.project_cap,tenant_cap=excluded.tenant_cap,enabled=true;
END $$;
REVOKE ALL ON FUNCTION evidence_budget_set_policy(uuid,uuid,boolean,text[],bigint,bigint) FROM PUBLIC;

CREATE FUNCTION evidence_budget_reserve(t uuid,p uuid,tr uuid,k text,m text,pr text,ep text,dm text,amt bigint,safe_max bigint)
RETURNS TABLE(reservation_id uuid,period_start timestamptz,replayed boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE pol evidence_budget_policy%ROWTYPE; old evidence_budget_reservations%ROWTYPE; day_start timestamptz; used numeric; tenant_limit bigint;
BEGIN
 IF amt<0 OR amt>safe_max OR safe_max<>9007199254740991 THEN RAISE EXCEPTION 'invalid safe budget amount'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(t::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(t::text||':'||p::text,0));
 SELECT * INTO pol FROM evidence_budget_policy WHERE tenant_id=t AND project_id=p FOR UPDATE;
 IF NOT FOUND OR NOT pol.enabled OR pol.frozen OR NOT (m=ANY(pol.allowed_models)) THEN RAISE EXCEPTION 'budget policy denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO old FROM evidence_budget_reservations WHERE tenant_id=t AND project_id=p AND idempotency_key=k FOR UPDATE;
 IF FOUND THEN
   IF old.turn_id<>tr OR old.model_id<>m OR old.provider<>pr OR old.endpoint_id<>ep OR old.destination_model_id<>dm OR old.reserved_amount<>amt THEN RAISE EXCEPTION 'budget idempotency conflict' USING ERRCODE='23505'; END IF;
   reservation_id:=old.reservation_id;period_start:=old.period_start;replayed:=true;RETURN NEXT;RETURN;
 END IF;
 day_start:=date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
 SELECT COALESCE(sum(CASE WHEN status='open' THEN GREATEST(reserved_amount,overrun_floor) WHEN status='settled' THEN COALESCE(actual_amount,0) ELSE 0 END),0) INTO used FROM evidence_budget_reservations WHERE tenant_id=t AND project_id=p AND (evidence_budget_reservations.period_start=day_start OR status='open');
 IF used+amt>pol.project_cap THEN RAISE EXCEPTION 'project budget exceeded' USING ERRCODE='54000'; END IF;
 SELECT min(q.tenant_cap) INTO tenant_limit FROM evidence_budget_policy q WHERE q.tenant_id=t;
 IF tenant_limit IS NOT NULL THEN
   SELECT COALESCE(sum(CASE WHEN status='open' THEN GREATEST(reserved_amount,overrun_floor) WHEN status='settled' THEN COALESCE(actual_amount,0) ELSE 0 END),0) INTO used FROM evidence_budget_reservations WHERE tenant_id=t AND (evidence_budget_reservations.period_start=day_start OR status='open');
   IF used+amt>tenant_limit THEN RAISE EXCEPTION 'tenant budget exceeded' USING ERRCODE='54000'; END IF;
 END IF;
 INSERT INTO evidence_budget_reservations(tenant_id,project_id,turn_id,idempotency_key,model_id,provider,endpoint_id,destination_model_id,reserved_amount,period_start)
 VALUES(t,p,tr,k,m,pr,ep,dm,amt,day_start) RETURNING evidence_budget_reservations.reservation_id,evidence_budget_reservations.period_start INTO reservation_id,period_start;
 replayed:=false;RETURN NEXT;
END $$;
REVOKE ALL ON FUNCTION evidence_budget_reserve(uuid,uuid,uuid,text,text,text,text,text,bigint,bigint) FROM PUBLIC;

CREATE FUNCTION evidence_budget_mark_dispatch(r uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE n int; BEGIN UPDATE evidence_budget_reservations SET dispatch_possible=true WHERE reservation_id=r AND status='open' AND NOT dispatch_possible;GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;END $$;
CREATE FUNCTION evidence_budget_release_unmarked(r uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE n int; BEGIN UPDATE evidence_budget_reservations SET status='released',actual_amount=0,settled_at=clock_timestamp() WHERE reservation_id=r AND status='open' AND NOT dispatch_possible;GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;END $$;
CREATE FUNCTION evidence_budget_settle(r uuid,exact_amount bigint,is_unknown boolean) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE x evidence_budget_reservations%ROWTYPE; amount bigint; tenant uuid; BEGIN
 SELECT tenant_id INTO tenant FROM evidence_budget_reservations WHERE reservation_id=r;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO x FROM evidence_budget_reservations WHERE reservation_id=r FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 IF x.status='settled' THEN RETURN x.unknown=is_unknown AND x.actual_amount IS NOT DISTINCT FROM (CASE WHEN is_unknown THEN GREATEST(x.reserved_amount,x.overrun_floor) ELSE exact_amount END); END IF;
 IF x.status<>'open' OR NOT x.dispatch_possible OR (is_unknown AND exact_amount IS NOT NULL) OR (NOT is_unknown AND (exact_amount IS NULL OR exact_amount<0 OR exact_amount>9007199254740991)) THEN RETURN false; END IF;
 IF NOT is_unknown AND exact_amount<x.overrun_floor THEN RETURN false; END IF;
 amount:=CASE WHEN is_unknown THEN GREATEST(x.reserved_amount,x.overrun_floor) ELSE exact_amount END;
 UPDATE evidence_budget_reservations SET status='settled',actual_amount=amount,unknown=is_unknown,overrun=(amount>reserved_amount),settled_at=clock_timestamp() WHERE reservation_id=r;
 IF amount>x.reserved_amount THEN
   UPDATE evidence_budget_policy SET frozen=true WHERE tenant_id=x.tenant_id AND (project_id=x.project_id OR EXISTS (SELECT 1 FROM evidence_budget_policy q WHERE q.tenant_id=x.tenant_id AND q.tenant_cap IS NOT NULL));
 END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION evidence_budget_mark_dispatch(uuid),evidence_budget_release_unmarked(uuid),evidence_budget_settle(uuid,bigint,boolean) FROM PUBLIC;

-- Preserve a measured overrun before attempting to publish output evidence.
CREATE FUNCTION evidence_budget_note_overrun(r uuid,amount bigint) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE x evidence_budget_reservations%ROWTYPE; tenant uuid;
BEGIN
 SELECT tenant_id INTO tenant FROM evidence_budget_reservations WHERE reservation_id=r;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO x FROM evidence_budget_reservations WHERE reservation_id=r FOR UPDATE;
 IF NOT FOUND OR x.status<>'open' OR NOT x.dispatch_possible OR amount<=x.reserved_amount OR amount>9007199254740991 THEN RETURN false; END IF;
 UPDATE evidence_budget_reservations SET overrun=true,overrun_floor=GREATEST(overrun_floor,amount) WHERE reservation_id=r;
 UPDATE evidence_budget_policy SET frozen=true WHERE tenant_id=x.tenant_id AND (project_id=x.project_id OR EXISTS (SELECT 1 FROM evidence_budget_policy q WHERE q.tenant_id=x.tenant_id AND q.tenant_cap IS NOT NULL));
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION evidence_budget_note_overrun(uuid,bigint) FROM PUBLIC;

CREATE FUNCTION evidence_budget_summary(t uuid,p uuid) RETURNS TABLE(period_start timestamptz,project_cap bigint,tenant_cap bigint,outstanding bigint,settled bigint,unknown bigint,remaining bigint,frozen boolean)
LANGUAGE sql SECURITY DEFINER SET search_path FROM CURRENT AS $$
 WITH pol AS (
   SELECT q.project_cap,q.enabled,q.frozen,
     (SELECT min(x.tenant_cap) FROM evidence_budget_policy x WHERE x.tenant_id=t) AS effective_tenant_cap
   FROM evidence_budget_policy q WHERE q.tenant_id=t AND q.project_id=p
 ), d AS (SELECT date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' v), sums AS (
   SELECT COALESCE(sum(GREATEST(reserved_amount,overrun_floor)) FILTER (WHERE status='open' AND project_id=p),0) o,
     COALESCE(sum(actual_amount) FILTER (WHERE status='settled' AND NOT unknown AND project_id=p),0) s,
     COALESCE(sum(actual_amount) FILTER (WHERE status='settled' AND unknown AND project_id=p),0) u,
     COALESCE(sum(CASE WHEN status='open' THEN GREATEST(reserved_amount,overrun_floor) WHEN status='settled' THEN actual_amount ELSE 0 END),0) tenant_exposure
   FROM evidence_budget_reservations,d WHERE tenant_id=t AND (evidence_budget_reservations.period_start=d.v OR status='open')
 )
 SELECT d.v,pol.project_cap,pol.effective_tenant_cap,sums.o::bigint,sums.s::bigint,sums.u::bigint,
    (CASE WHEN pol.frozen OR NOT pol.enabled THEN 0 ELSE GREATEST(0,LEAST(pol.project_cap-sums.o-sums.s-sums.u,pol.effective_tenant_cap-sums.tenant_exposure)) END)::bigint,
    pol.frozen FROM pol,d,sums $$;
REVOKE ALL ON FUNCTION evidence_budget_summary(uuid,uuid) FROM PUBLIC;
DO $$
DECLARE fn record;
BEGIN
  BEGIN CREATE ROLE charter_budget_app NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO charter_budget_app', current_schema());
  -- Put pg_temp last so transient relations cannot shadow the trusted schema.
  FOR fn IN SELECT p.oid::regprocedure AS sig FROM pg_proc p WHERE p.pronamespace=current_schema()::regnamespace AND p.proname LIKE 'evidence_budget_%' LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog,%I,pg_temp',fn.sig,current_schema());
  END LOOP;
END $$;
GRANT SELECT ON evidence_budget_policy,evidence_budget_reservations TO charter_budget_app;
GRANT EXECUTE ON FUNCTION evidence_budget_reserve(uuid,uuid,uuid,text,text,text,text,text,bigint,bigint),evidence_budget_mark_dispatch(uuid),evidence_budget_release_unmarked(uuid),evidence_budget_settle(uuid,bigint,boolean),evidence_budget_note_overrun(uuid,bigint),evidence_budget_summary(uuid,uuid) TO charter_budget_app;
