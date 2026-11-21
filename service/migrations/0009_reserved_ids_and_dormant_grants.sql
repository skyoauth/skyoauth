-- Two database backstops for registry rules that only the service enforced
-- until now (lead decisions, 2026-11-21; provisional until the maintainer
-- ratifies the ADRs, T00.8 to T00.17): no operator identity takes an actor
-- ID reserved for an actor that is not an operator identity, and an
-- impersonation grant, which v0.1 stores only dormant, never changes after
-- the transaction that creates it (design section 5.6: unsupported
-- impersonation records "remain unchanged and inactive"; T10.11, T12.10).
-- The conventions of 0002 to 0008 apply. "(inferred)" marks a choice the
-- specifications and lead decisions do not dictate; README.md "What 0009
-- adds" has the upgrade precondition.

-- Reserved actor IDs (identity-registry section 5.2): exactly
-- 'deployment_operator', the actor of bootstrap, and every ID that begins
-- with 'recovery_key:', the actors of the offline recovery keys. The rule is
-- the registry's is_reserved_actor_id(): byte-wise, with no case folding,
-- so 'Recovery_Key:1', 'recovery_key' and 'deployment_operator ' are other
-- IDs. The registry rejects a reserved ID before its statement
-- (ReservedActorId); this check is the backstop for every other writer.
-- starts_with() compares bytes, as the column is COLLATE "C", and unlike
-- LIKE gives '_' and '%' no meaning (inferred).
--
-- A plain ADD CONSTRAINT, which validates every existing row in the same
-- statement (inferred): NOT VALID followed by VALIDATE CONSTRAINT would
-- shorten nothing here, since the migration runs in one transaction and the
-- ACCESS EXCLUSIVE lock of ADD CONSTRAINT is held until it commits anyway,
-- and admin_identity holds a few rows per instance. A row that fails makes
-- the migration fail with 23514 and roll back (README.md "What 0009 adds",
-- "Upgrade precondition").
ALTER TABLE admin_identity
    ADD CONSTRAINT admin_identity_id_not_reserved_check
        CHECK (id <> 'deployment_operator' AND NOT starts_with(id, 'recovery_key:'));

-- Rejects every UPDATE of an impersonation grant, and every UPDATE that
-- would make a grant one or stop one being one (lead ruling, 2026-11-21:
-- the grant is frozen entirely). mode is immutable since 0004
-- (service_grant_immutable), so the NEW.mode test is a second line for the
-- day that trigger is dropped or disabled. The guard does not compare NEW
-- with OLD: every UPDATE of service_grant must advance revision by one
-- (service_grant_revision), so no UPDATE leaves a row as it was, and the
-- guard rejects even one that would change nothing else (inferred). A
-- creating transaction needs no UPDATE: the grant row is inserted complete.
-- It resolves no table, so it pins only pg_catalog and pg_temp.
CREATE FUNCTION skyoauth_reject_impersonation_grant_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    IF OLD.mode IS NOT DISTINCT FROM 'impersonation'
        OR NEW.mode IS NOT DISTINCT FROM 'impersonation' THEN
        RAISE EXCEPTION 'an impersonation grant of % is never updated', TG_TABLE_NAME
            USING ERRCODE = 'SK001';
    END IF;
    RETURN NEW;
END;
$$;

-- Rejects an INSERT, UPDATE or DELETE of a row of service_grant_binding or
-- service_grant_resource_server whose grant is an impersonation grant that
-- the current transaction did not create. The creating transaction inserts
-- the list rows after the grant row (the deferred 0004 check requires a
-- binding row at commit), so it may still add, change and delete them; once
-- it commits, the set is frozen with the grant. A row whose grant is not
-- visible (deleted in this transaction, or missing under
-- session_replication_role = replica, where foreign keys do not fire) is
-- left alone.
--
-- "Created by the current transaction" is decided from the xmin of the
-- grant row, which an UPDATE would change but this migration forbids
-- (above) and a row lock leaves alone. pg_current_xact_id() is the
-- top-level transaction ID, but a grant inserted inside a savepoint carries
-- the subtransaction's ID, which is newer, so an equality test would
-- misjudge it. Instead the 32-bit xmin is widened to an xid8 in the epoch of
-- the top-level ID (subtransaction IDs are assigned after it, and xmin is
-- at most 2^31 transactions away from it while the row is unfrozen), and
-- pg_xact_status() says whether that transaction is in progress. It is 'in
-- progress' for the top-level ID and every live or released subtransaction
-- of the current transaction, and an in-progress transaction whose row the
-- trigger can see is the current one: MVCC never shows another
-- transaction's uncommitted row. A grant row from a rolled-back savepoint
-- is not visible at all (and its foreign keys reject the list row). An
-- xmin older than the top-level ID is not the current transaction's.
-- pg_locks cannot replace pg_xact_status(): a released savepoint gives up
-- the lock on its own ID. Limit: a row frozen by VACUUM keeps its raw xmin,
-- which widens to an ID that may be in the future (pg_xact_status() then
-- fails with 22023, caught below: not created here) or, after 2^32 more
-- transactions in the cluster, equal to the ID of a transaction in
-- progress, which then counts as having created the grant.
--
-- The trigger is AFTER ... FOR EACH ROW, not BEFORE (inferred): it then
-- runs after the foreign-key check of the inserted row (its internal
-- trigger, "RI_ConstraintTrigger_c_<oid>", sorts first byte-wise and
-- PostgreSQL fires the AFTER triggers of an event in name order) and with a
-- newer snapshot, so under READ COMMITTED a grant that a concurrent
-- transaction committed after a BEFORE trigger had looked, but before the
-- foreign key checked, is seen as the other transaction's and rejected. A
-- rejected statement still changes nothing. Being AFTER, a row that breaks a
-- NOT NULL or CHECK constraint fails with that error first, as before.
--
-- The function reads service_grant, so it is created as the 0004 check is:
-- schema resolved by current_schema(), pinned search_path, the table named
-- with the schema, body passed as a quoted literal (%L). It runs with the
-- caller's privileges: a role that writes the list rows needs SELECT on
-- service_grant (README.md "What 0009 adds").
DO $migration$
DECLARE
    schema_name constant text := current_schema();
BEGIN
    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, %I, pg_temp
    AS %L', 'skyoauth_reject_impersonation_grant_list_change', schema_name,
        replace($body$
DECLARE
    grant_keys text[];
    grant_key text COLLATE "C";
    grant_xmin xid;
    top_xid bigint;
    ahead bigint;
    created_here boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        grant_keys := ARRAY[NEW.grant_id];
    ELSIF TG_OP = 'DELETE' THEN
        grant_keys := ARRAY[OLD.grant_id];
    ELSE
        grant_keys := ARRAY[OLD.grant_id, NEW.grant_id];
    END IF;
    FOREACH grant_key IN ARRAY grant_keys LOOP
        SELECT g.xmin INTO grant_xmin FROM @schema@.service_grant g
            WHERE g.id = grant_key AND g.mode = 'impersonation';
        CONTINUE WHEN NOT FOUND;
        top_xid := pg_current_xact_id()::text::bigint;
        -- How far xmin is ahead of the top-level ID, modulo 2^32.
        ahead := (grant_xmin::text::bigint - top_xid) & 4294967295;
        created_here := false;
        IF ahead < 2147483648 THEN
            BEGIN
                created_here := pg_xact_status((top_xid + ahead)::text::xid8)
                    IS NOT DISTINCT FROM 'in progress';
            EXCEPTION WHEN invalid_parameter_value THEN
                -- "transaction ID ... is in the future": a frozen row's raw
                -- xmin, not the current transaction's.
                created_here := false;
            END;
        END IF;
        IF NOT created_here THEN
            RAISE EXCEPTION 'the rows of % of an impersonation grant change only in the transaction that creates it',
                TG_TABLE_NAME
                USING ERRCODE = 'SK001';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$body$, '@schema@', quote_ident(schema_name)));
END;
$migration$;

-- The grant row: no UPDATE of an impersonation grant, in any transaction.
CREATE TRIGGER service_grant_impersonation_frozen
    BEFORE UPDATE ON service_grant
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_impersonation_grant_update();
ALTER TABLE service_grant ENABLE ALWAYS TRIGGER service_grant_impersonation_frozen;

-- Its list rows: changed only by the transaction that creates the grant.
-- The 0006 delete guard of service_grant is unchanged: an impersonation
-- grant is still never deleted.
CREATE TRIGGER service_grant_binding_impersonation_frozen
    AFTER INSERT OR UPDATE OR DELETE ON service_grant_binding
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_impersonation_grant_list_change();
ALTER TABLE service_grant_binding ENABLE ALWAYS TRIGGER service_grant_binding_impersonation_frozen;

CREATE TRIGGER service_grant_resource_server_impersonation_frozen
    AFTER INSERT OR UPDATE OR DELETE ON service_grant_resource_server
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_impersonation_grant_list_change();
ALTER TABLE service_grant_resource_server
    ENABLE ALWAYS TRIGGER service_grant_resource_server_impersonation_frozen;
