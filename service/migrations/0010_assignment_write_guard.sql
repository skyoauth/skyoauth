-- A database guard for IR-080 assignment references (T14.2;
-- docs/proposals/ir-080-assignment-write-guard.md, accepted by the user and
-- relayed by the lead, 2026-11-22). Every pick here is a provisional lead
-- pick, 2026-11-22, until the maintainer ratifies the ADRs (T00.8 to
-- T00.17, Gate M0). The conventions of 0002 to 0009 apply. "(inferred)"
-- marks a choice the proposal and the lead rulings do not dictate;
-- README.md "What 0010 adds" has the lock order and the limits.
--
-- A service identity or a grant may reference a resource server only
-- through an enabled ("active") same-tenant assignment (IR-080). The
-- composite foreign keys of 0004 from service_identity_resource_server and
-- service_grant_resource_server to audience_tenant_assignment prove only
-- that the assignment exists. A check-then-insert above the registry races:
-- the foreign key takes FOR KEY SHARE on the assignment row, which does not
-- conflict with the FOR NO KEY UPDATE lock of an UPDATE of its status, so a
-- disable can commit between the check and the insert. The guard below
-- reads the assignment FOR SHARE, which does conflict with that UPDATE, so
-- an insert and a concurrent disable serialize: whichever comes second sees
-- the other's result. Under READ COMMITTED an insert that waited for a
-- disable then sees it and is refused; under REPEATABLE READ or
-- SERIALIZABLE it fails with 40001 (serialization_failure) instead.
--
-- The triggers are AFTER INSERT ... FOR EACH ROW, not deferrable, as the
-- 0009 list guard is (provisional lead pick, 2026-11-22, after review). An
-- AFTER row trigger runs at the end of the statement, after the row is in
-- the table and its indexes, and PostgreSQL fires the AFTER triggers of a
-- row in name order: the foreign-key check, an internal trigger named
-- "RI_ConstraintTrigger_c_<oid>", sorts before these names byte-wise
-- ('R' < 's'), so it runs first and the guard reads the assignment after
-- it, with a newer snapshot. The trigger names must keep sorting after
-- "RI_"; a rename that breaks this changes the order. Under READ COMMITTED
-- a BEFORE trigger lets a row through when another transaction inserts its
-- assignment 'disabled' and commits between the guard (no row yet) and the
-- foreign-key check at the end of the statement (found); after the foreign
-- key, the guard sees that assignment and refuses the row. A DEFERRED
-- trigger would take the FOR SHARE lock at commit, after the audit head,
-- which inverts the lock order below, and would fail at COMMIT. Being AFTER
-- also means: a row that breaks a NOT NULL, CHECK or unique constraint, or
-- whose assignment is missing, fails with that error first; an INSERT ...
-- ON CONFLICT DO NOTHING that inserts no row fires no guard; and the guard
-- sees every change its own statement made, so the state of the
-- assignment at the end of the statement decides (README.md "What 0010
-- adds", "Limits").
--
-- A present assignment that is not enabled is refused with check_violation
-- (23514) naming a constraint, the trigger's own name, so the registry maps
-- it to a typed error, not to the SK001 guard error. A missing assignment
-- is left to the foreign key (23503), which runs first; the guard finds no
-- row only where the foreign key does not fire (replica mode) and returns.
-- Only INSERT is guarded: 0004 makes every column of these list rows
-- immutable (the *_immutable guards), and a DELETE needs no check. A
-- rejected statement changes nothing.
--
-- Carried over from the lead rulings of 2026-11-21 (proposal, decisions 2
-- to 4): the guard does not read resource_server.status, so a disabled
-- resource server stays a valid dormant reference at write and the live
-- check denies it (IR-081); it checks only at insert, so enabling or
-- disabling an assignment later revalidates no existing row; and disabling
-- an assignment that rows reference is not blocked (stranding is fine).
--
-- The function reads audience_tenant_assignment, so it is created as the
-- 0009 list guard is, with the schema resolved by current_schema() at
-- migrate time, the table named with that schema and the body passed as a
-- quoted literal (%L). Its search_path is pinned to pg_catalog, pg_temp
-- only (lead pick): every table it reads is named with its schema, so no
-- name resolves through the schema. It is SECURITY INVOKER, the default,
-- like every guard: a role that inserts these list rows needs SELECT on
-- audience_tenant_assignment (tenant_id, resource_server_id and status)
-- and, because a FOR SHARE lock requires it, UPDATE on at least one of its
-- columns; the prescribed grant is UPDATE (id), a key column that the 0003
-- guard audience_tenant_assignment_immutable keeps unchangeable (README.md
-- "What 0010 adds", "Privileges").
--
-- One function serves both triggers (inferred, as for the 0009 list
-- guard): the constraint it names is TG_NAME, the name of the trigger that
-- fired, so each table's refusal names that table's trigger.
DO $migration$
DECLARE
    schema_name constant text := current_schema();
BEGIN
    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS %L', 'skyoauth_require_active_assignment',
        replace($body$
DECLARE
    assignment_status text;
BEGIN
    SELECT a.status INTO assignment_status
        FROM @schema@.audience_tenant_assignment a
        WHERE a.tenant_id = NEW.tenant_id AND a.resource_server_id = NEW.resource_server_id
        FOR SHARE;
    IF FOUND AND assignment_status IS DISTINCT FROM 'enabled' THEN
        RAISE EXCEPTION 'a row of % needs an enabled audience tenant assignment', TG_TABLE_NAME
            USING ERRCODE = 'check_violation', CONSTRAINT = TG_NAME,
                  TABLE = TG_TABLE_NAME, SCHEMA = TG_TABLE_SCHEMA;
    END IF;
    RETURN NULL;
END;
$body$, '@schema@', quote_ident(schema_name)));
END;
$migration$;

-- A service identity's audiences.
CREATE TRIGGER service_identity_resource_server_assignment_active
    AFTER INSERT ON service_identity_resource_server
    FOR EACH ROW EXECUTE FUNCTION skyoauth_require_active_assignment();
ALTER TABLE service_identity_resource_server
    ENABLE ALWAYS TRIGGER service_identity_resource_server_assignment_active;

-- A grant's audiences.
CREATE TRIGGER service_grant_resource_server_assignment_active
    AFTER INSERT ON service_grant_resource_server
    FOR EACH ROW EXECUTE FUNCTION skyoauth_require_active_assignment();
ALTER TABLE service_grant_resource_server
    ENABLE ALWAYS TRIGGER service_grant_resource_server_assignment_active;
