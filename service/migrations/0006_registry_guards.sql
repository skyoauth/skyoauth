-- Delete and truncate guards for every registry table of 0002 to 0005, and
-- the pruning index of consumed_assertion (T10.1, T10.9). They are the one
-- follow-up migration for all registry tables, decided together (lead
-- decision, 2026-11-20; README.md "What 0006 adds" has the per-table rules).
-- The conventions of 0002 to 0005 apply. "(inferred)" marks a choice the
-- specifications do not dictate.
--
-- Rows are disabled through status, not deleted (ADR-008 item 3: "removal
-- of anything referenced or enabled is soft disable only"). A row that is
-- deleted and created again with the same ID starts again at revision 1, so
-- an old (id, revision) snapshot could match the new row; deleting one-time
-- state (bootstrap, recovery, operations, consumed proofs) undoes it. Every
-- guard raises SK001 and is ENABLE ALWAYS, so it also fires under
-- session_replication_role = replica. Like the earlier guards they are a
-- tripwire against application DML, not a security boundary.
--
-- DELETE is guarded by a BEFORE DELETE ... FOR EACH ROW trigger, so a
-- DELETE that matches no row passes and a rejected one deletes nothing.
-- TRUNCATE is guarded by a BEFORE TRUNCATE ... FOR EACH STATEMENT trigger
-- on every table, the list tables included: TRUNCATE skips row triggers and
-- the deferred binding-set check of 0004, and TRUNCATE ... CASCADE fires the
-- BEFORE TRUNCATE triggers of every table it reaches, so a cascade from
-- another table is rejected too. The 0001 and 0002 tables that already have
-- such guards (schema_info, instance_security_policy, egress_allowlist_entry,
-- audit_event, audit_chain_head) are unchanged.
--
-- The guards do not reuse skyoauth_reject_mutation() of 0001: its message
-- calls the table "append-only", which is false here: the rows of these
-- tables stay updatable, except consumed_assertion, whose rows are pruned
-- (lead decision, 2026-11-21). The unconditional guards
-- call skyoauth_reject_delete() and skyoauth_reject_truncate(), whose
-- messages name the operation and the table. None of the new guard
-- functions reads a table: each pins search_path to pg_catalog, pg_temp, as
-- the 0002 and 0005 guards that read none do.

-- Rejects every DELETE of a row of the table it guards.
CREATE FUNCTION skyoauth_reject_delete() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    RAISE EXCEPTION 'DELETE is not allowed on %', TG_TABLE_NAME
        USING ERRCODE = 'SK001';
END;
$$;

-- Rejects every TRUNCATE of the table it guards, also one that reaches it
-- through TRUNCATE ... CASCADE.
CREATE FUNCTION skyoauth_reject_truncate() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    RAISE EXCEPTION 'TRUNCATE is not allowed on %', TG_TABLE_NAME
        USING ERRCODE = 'SK001';
END;
$$;

-- Rejects a DELETE of a row whose status is not 'disabled' (ADR-008 item 3:
-- only a disabled, unreferenced binding or grant may be hard-deleted). The
-- foreign keys that reference the row reject a referenced one with 23503,
-- after this guard.
CREATE FUNCTION skyoauth_reject_delete_unless_disabled() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM 'disabled' THEN
        RAISE EXCEPTION 'only a disabled row of % may be deleted', TG_TABLE_NAME
            USING ERRCODE = 'SK001';
    END IF;
    RETURN OLD;
END;
$$;

-- Rejects a DELETE of a consumed proof whose retention has not ended: only
-- rows with retain_until < now() may be pruned, so a replay within the
-- retention window still conflicts (T10.9; lifetimes section 9). now() is
-- the start time of the deleting transaction; a row whose retain_until
-- equals it is kept (inferred: strictly after).
CREATE FUNCTION skyoauth_reject_delete_before_retention() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    IF (OLD.retain_until < now()) IS NOT TRUE THEN
        RAISE EXCEPTION 'a row of % cannot be deleted before its retain_until', TG_TABLE_NAME
            USING ERRCODE = 'SK001';
    END IF;
    RETURN OLD;
END;
$$;

-- Never deleted: 0002 tenants and principals (README.md "disable tenants and
-- principals through status"), the four revisioned 0003 tables and the 0004
-- keysets, keyset versions, sources and service identities (ADR-008 item 3
-- allows a hard delete only of bindings and grants, and no source defines
-- one for these tables: they are offboarded by disabling them, and a later
-- forward migration can relax a guard if a specification defines a hard
-- delete; lead decision, 2026-11-21), and the 0005 operator identities,
-- credentials, role bindings, recovery state and administrative operations
-- (README.md follow-up, lead decisions 2026-11-21). A credential, revoked
-- or not, leaves service by revocation (T13.6): deleting its row would
-- erase the revocation record and free its public_identity, so the key
-- could be registered again.
CREATE TRIGGER tenant_no_delete
    BEFORE DELETE ON tenant
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE tenant ENABLE ALWAYS TRIGGER tenant_no_delete;

CREATE TRIGGER principal_no_delete
    BEFORE DELETE ON principal
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE principal ENABLE ALWAYS TRIGGER principal_no_delete;

CREATE TRIGGER resource_server_no_delete
    BEFORE DELETE ON resource_server
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE resource_server ENABLE ALWAYS TRIGGER resource_server_no_delete;

CREATE TRIGGER audience_tenant_assignment_no_delete
    BEFORE DELETE ON audience_tenant_assignment
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE audience_tenant_assignment ENABLE ALWAYS TRIGGER audience_tenant_assignment_no_delete;

CREATE TRIGGER resource_server_checker_no_delete
    BEFORE DELETE ON resource_server_checker
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE resource_server_checker ENABLE ALWAYS TRIGGER resource_server_checker_no_delete;

CREATE TRIGGER resource_action_no_delete
    BEFORE DELETE ON resource_action
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE resource_action ENABLE ALWAYS TRIGGER resource_action_no_delete;

CREATE TRIGGER trust_keyset_no_delete
    BEFORE DELETE ON trust_keyset
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE trust_keyset ENABLE ALWAYS TRIGGER trust_keyset_no_delete;

CREATE TRIGGER trust_keyset_version_no_delete
    BEFORE DELETE ON trust_keyset_version
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE trust_keyset_version ENABLE ALWAYS TRIGGER trust_keyset_version_no_delete;

CREATE TRIGGER trust_source_no_delete
    BEFORE DELETE ON trust_source
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE trust_source ENABLE ALWAYS TRIGGER trust_source_no_delete;

CREATE TRIGGER service_identity_no_delete
    BEFORE DELETE ON service_identity
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE service_identity ENABLE ALWAYS TRIGGER service_identity_no_delete;

CREATE TRIGGER admin_identity_no_delete
    BEFORE DELETE ON admin_identity
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE admin_identity ENABLE ALWAYS TRIGGER admin_identity_no_delete;

CREATE TRIGGER admin_credential_no_delete
    BEFORE DELETE ON admin_credential
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE admin_credential ENABLE ALWAYS TRIGGER admin_credential_no_delete;

CREATE TRIGGER admin_role_binding_no_delete
    BEFORE DELETE ON admin_role_binding
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE admin_role_binding ENABLE ALWAYS TRIGGER admin_role_binding_no_delete;

CREATE TRIGGER recovery_state_no_delete
    BEFORE DELETE ON recovery_state
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE recovery_state ENABLE ALWAYS TRIGGER recovery_state_no_delete;

CREATE TRIGGER administrative_operation_no_delete
    BEFORE DELETE ON administrative_operation
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete();
ALTER TABLE administrative_operation ENABLE ALWAYS TRIGGER administrative_operation_no_delete;

-- Deleted only when disabled: a binding (by an audited admin write, when no
-- grant, approval or audit-required record references it) and a grant
-- (with its list rows deleted first), ADR-008 item 3. A grant's binding
-- rows and a binding's grant rows reference them, so the foreign keys
-- refuse a referenced one (23503).
CREATE TRIGGER principal_binding_delete_disabled_only
    BEFORE DELETE ON principal_binding
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete_unless_disabled();
ALTER TABLE principal_binding ENABLE ALWAYS TRIGGER principal_binding_delete_disabled_only;

CREATE TRIGGER service_grant_delete_disabled_only
    BEFORE DELETE ON service_grant
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete_unless_disabled();
ALTER TABLE service_grant ENABLE ALWAYS TRIGGER service_grant_delete_disabled_only;

-- A consumed proof is pruned only after its retention.
CREATE TRIGGER consumed_assertion_delete_after_retention
    BEFORE DELETE ON consumed_assertion
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_delete_before_retention();
ALTER TABLE consumed_assertion ENABLE ALWAYS TRIGGER consumed_assertion_delete_after_retention;

-- The list tables (resource_server_checker_tenant,
-- service_identity_resource_server, service_grant_binding and
-- service_grant_resource_server) keep DELETE: deleting a row is how such a
-- set shrinks, and the owner's revision records it. Only TRUNCATE is
-- guarded on them. For service_grant_binding the README requires it (a
-- TRUNCATE skips the deferred binding-set check and leaves grants with no
-- binding); for the other three it is inferred (a TRUNCATE would empty
-- every owner's set without advancing any revision).
--
-- No TRUNCATE of any registry table of 0002 to 0005.
CREATE TRIGGER tenant_no_truncate
    BEFORE TRUNCATE ON tenant
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE tenant ENABLE ALWAYS TRIGGER tenant_no_truncate;

CREATE TRIGGER principal_no_truncate
    BEFORE TRUNCATE ON principal
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE principal ENABLE ALWAYS TRIGGER principal_no_truncate;

CREATE TRIGGER resource_server_no_truncate
    BEFORE TRUNCATE ON resource_server
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE resource_server ENABLE ALWAYS TRIGGER resource_server_no_truncate;

CREATE TRIGGER audience_tenant_assignment_no_truncate
    BEFORE TRUNCATE ON audience_tenant_assignment
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE audience_tenant_assignment ENABLE ALWAYS TRIGGER audience_tenant_assignment_no_truncate;

CREATE TRIGGER resource_server_checker_no_truncate
    BEFORE TRUNCATE ON resource_server_checker
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE resource_server_checker ENABLE ALWAYS TRIGGER resource_server_checker_no_truncate;

CREATE TRIGGER resource_server_checker_tenant_no_truncate
    BEFORE TRUNCATE ON resource_server_checker_tenant
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE resource_server_checker_tenant
    ENABLE ALWAYS TRIGGER resource_server_checker_tenant_no_truncate;

CREATE TRIGGER resource_action_no_truncate
    BEFORE TRUNCATE ON resource_action
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE resource_action ENABLE ALWAYS TRIGGER resource_action_no_truncate;

CREATE TRIGGER trust_keyset_no_truncate
    BEFORE TRUNCATE ON trust_keyset
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE trust_keyset ENABLE ALWAYS TRIGGER trust_keyset_no_truncate;

CREATE TRIGGER trust_keyset_version_no_truncate
    BEFORE TRUNCATE ON trust_keyset_version
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE trust_keyset_version ENABLE ALWAYS TRIGGER trust_keyset_version_no_truncate;

CREATE TRIGGER trust_source_no_truncate
    BEFORE TRUNCATE ON trust_source
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE trust_source ENABLE ALWAYS TRIGGER trust_source_no_truncate;

CREATE TRIGGER principal_binding_no_truncate
    BEFORE TRUNCATE ON principal_binding
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE principal_binding ENABLE ALWAYS TRIGGER principal_binding_no_truncate;

CREATE TRIGGER service_identity_no_truncate
    BEFORE TRUNCATE ON service_identity
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE service_identity ENABLE ALWAYS TRIGGER service_identity_no_truncate;

CREATE TRIGGER service_identity_resource_server_no_truncate
    BEFORE TRUNCATE ON service_identity_resource_server
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE service_identity_resource_server
    ENABLE ALWAYS TRIGGER service_identity_resource_server_no_truncate;

CREATE TRIGGER service_grant_no_truncate
    BEFORE TRUNCATE ON service_grant
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE service_grant ENABLE ALWAYS TRIGGER service_grant_no_truncate;

CREATE TRIGGER service_grant_binding_no_truncate
    BEFORE TRUNCATE ON service_grant_binding
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE service_grant_binding ENABLE ALWAYS TRIGGER service_grant_binding_no_truncate;

CREATE TRIGGER service_grant_resource_server_no_truncate
    BEFORE TRUNCATE ON service_grant_resource_server
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE service_grant_resource_server
    ENABLE ALWAYS TRIGGER service_grant_resource_server_no_truncate;

CREATE TRIGGER admin_identity_no_truncate
    BEFORE TRUNCATE ON admin_identity
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE admin_identity ENABLE ALWAYS TRIGGER admin_identity_no_truncate;

CREATE TRIGGER admin_credential_no_truncate
    BEFORE TRUNCATE ON admin_credential
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE admin_credential ENABLE ALWAYS TRIGGER admin_credential_no_truncate;

CREATE TRIGGER admin_role_binding_no_truncate
    BEFORE TRUNCATE ON admin_role_binding
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE admin_role_binding ENABLE ALWAYS TRIGGER admin_role_binding_no_truncate;

CREATE TRIGGER recovery_state_no_truncate
    BEFORE TRUNCATE ON recovery_state
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE recovery_state ENABLE ALWAYS TRIGGER recovery_state_no_truncate;

CREATE TRIGGER administrative_operation_no_truncate
    BEFORE TRUNCATE ON administrative_operation
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE administrative_operation ENABLE ALWAYS TRIGGER administrative_operation_no_truncate;

CREATE TRIGGER consumed_assertion_no_truncate
    BEFORE TRUNCATE ON consumed_assertion
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_truncate();
ALTER TABLE consumed_assertion ENABLE ALWAYS TRIGGER consumed_assertion_no_truncate;

-- Pruning: no pruning job exists yet. The guard above only permits a
-- DELETE after retain_until; a later service job is to delete expired
-- proofs with DELETE FROM consumed_assertion WHERE retain_until < now(),
-- which this index serves without a scan of the whole table.
CREATE INDEX consumed_assertion_retain_until_idx ON consumed_assertion (retain_until);
