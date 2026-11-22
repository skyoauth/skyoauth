-- A database backstop for the IR-152 egress check of a trust source: a
-- write that sets discovery_url or token_review_endpoint to a destination
-- without an enabled egress_allowlist_entry of its purpose is rejected,
-- whoever writes it (provisional lead pick, 2026-11-22; provisional until
-- the maintainer ratifies the ADRs, T00.8 to T00.17, Gate M0). Until now
-- only the service checked it (skyoauth_service::trust::source), and the
-- registry writers and raw SQL wrote any destination the 0004 checks allow.
-- The service keeps its own check, which still refuses first
-- (EgressNotAllowed); this one is defense in depth. The conventions of 0002
-- to 0009 apply. "(inferred)" marks a choice the specifications and lead
-- decisions do not dictate; README.md "What 0011 adds" has the details.
--
-- The rule is the service's (README.md "Trust source writes"), for the two
-- destination columns of 0004 only, checked in a fixed order:
-- discovery_url against an entry of purpose 'oidc_discovery', then
-- token_review_endpoint against one of purpose 'token_review'. A member is
-- checked on INSERT when it is not NULL, and on UPDATE only when it is not
-- NULL and IS DISTINCT FROM its old value: the 0004 comment on these
-- columns says a write that leaves them unchanged must not be rejected for
-- a missing or disabled entry (IR-152: such a source is degraded at fetch,
-- not refused at write). A NULL member is never checked; the 0004 kind
-- checks decide which members a kind has. Existing rows are never
-- revalidated, by this migration or later: an entry disabled after a
-- source was written leaves that source as it is.
--
-- The match is the service's LOCK_ENTRY predicate: purpose = <purpose> AND
-- exact_destination = <member>, exact byte equality (both columns are
-- COLLATE "C", and the comparison names "C" too), no normalization. At
-- most one row matches, by the unique key (purpose, exact_destination). No
-- row, or a row whose status is not 'enabled', fails the write with
-- check_violation (23514) naming a per-member constraint,
-- trust_source_discovery_url_egress_enabled or
-- trust_source_token_review_endpoint_egress_enabled (lead decision), so the
-- registry maps it to Invariant { kind: Check, constraint } by name, as the
-- 0008 and 0009 checks; unlike the SK001 guards, it is a rule on the
-- row's values, not on the operation. The message names the column and
-- the purpose, never a value. A future destination column adds its own
-- check, constraint name and test here or in a later migration; this
-- function does not cover it.
--
-- The entry row is locked FOR SHARE, as the service locks it: a concurrent
-- UPDATE that disables the entry takes FOR NO KEY UPDATE, which conflicts,
-- so under READ COMMITTED either the disable waits until the write commits
-- or rolls back, or the write waits for the disable and then reads the row
-- as committed, 'disabled', and is refused. Under REPEATABLE READ and
-- SERIALIZABLE a lock on an entry changed after the snapshot fails with
-- 40001 (the registry's Retry). Lock order: on UPDATE, a BEFORE ROW trigger
-- fires after PostgreSQL has locked the target row, so the order is the
-- service's (operator rows, the source row, the entry FOR SHARE, discovery
-- before token_review, then the audit head); on INSERT the entry comes
-- before the foreign-key checks of the new row (tenant, keyset), which are
-- AFTER triggers. An egress entry writer must still lock no trust_source
-- row after an entry row, or it can deadlock with a source update (40P01,
-- Retry).
--
-- The trigger is BEFORE INSERT OR UPDATE ... FOR EACH ROW. PostgreSQL fires
-- the BEFORE row triggers of an event in name order, so
-- trust_source_egress_enabled fires before trust_source_immutable and
-- trust_source_revision (0004), and before the CHECK, NOT NULL, unique and
-- foreign-key constraints: a write that both changes an immutable column
-- and sets a destination without an enabled entry fails with this 23514,
-- not with SK001 (lead ruling). A destination that a 0004 column check
-- rejects (empty, with whitespace or a control character, over 2048 bytes)
-- matches no entry either, since exact_destination has the same checks
-- (0002), so it too fails here first (inferred consequence).
--
-- ENABLE ALWAYS, as every guard, so it fires under
-- session_replication_role = replica as well; a role that may switch
-- triggers off (the table owner, ALTER TABLE ... DISABLE TRIGGER) is not
-- stopped (README.md "Limits"). In replica mode the foreign keys do not
-- fire, but this trigger does.
--
-- The function reads egress_allowlist_entry, so the table is named with
-- the schema this migration runs in, resolved by current_schema(), and the
-- body is passed as a quoted literal (%L), as in 0002, 0004 and 0009. It
-- pins search_path to pg_catalog, pg_temp (lead decision): it resolves no
-- unqualified table, so the schema need not be on its path. It runs with
-- the caller's privileges (SECURITY INVOKER, the default): a role that
-- writes a trust source destination needs SELECT and UPDATE (for the row
-- lock) on egress_allowlist_entry, as the service's own LOCK_ENTRY does.
DO $migration$
DECLARE
    schema_name constant text := current_schema();
BEGIN
    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS %L', 'skyoauth_check_trust_source_egress',
        replace($body$
DECLARE
    check_discovery boolean;
    check_token_review boolean;
    entry_status text COLLATE "C";
BEGIN
    IF TG_OP = 'INSERT' THEN
        check_discovery := NEW.discovery_url IS NOT NULL;
        check_token_review := NEW.token_review_endpoint IS NOT NULL;
    ELSE
        check_discovery := NEW.discovery_url IS NOT NULL
            AND NEW.discovery_url IS DISTINCT FROM OLD.discovery_url;
        check_token_review := NEW.token_review_endpoint IS NOT NULL
            AND NEW.token_review_endpoint IS DISTINCT FROM OLD.token_review_endpoint;
    END IF;

    IF check_discovery THEN
        SELECT e.status INTO entry_status FROM @schema@.egress_allowlist_entry e
            WHERE e.purpose = 'oidc_discovery'
              AND e.exact_destination = (NEW.discovery_url COLLATE "C")
            FOR SHARE;
        IF NOT FOUND OR entry_status IS DISTINCT FROM 'enabled' THEN
            RAISE EXCEPTION '% discovery_url matches no enabled egress allowlist entry of purpose oidc_discovery',
                TG_TABLE_NAME
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'trust_source_discovery_url_egress_enabled',
                      SCHEMA = TG_TABLE_SCHEMA, TABLE = TG_TABLE_NAME,
                      COLUMN = 'discovery_url';
        END IF;
    END IF;

    IF check_token_review THEN
        SELECT e.status INTO entry_status FROM @schema@.egress_allowlist_entry e
            WHERE e.purpose = 'token_review'
              AND e.exact_destination = (NEW.token_review_endpoint COLLATE "C")
            FOR SHARE;
        IF NOT FOUND OR entry_status IS DISTINCT FROM 'enabled' THEN
            RAISE EXCEPTION '% token_review_endpoint matches no enabled egress allowlist entry of purpose token_review',
                TG_TABLE_NAME
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'trust_source_token_review_endpoint_egress_enabled',
                      SCHEMA = TG_TABLE_SCHEMA, TABLE = TG_TABLE_NAME,
                      COLUMN = 'token_review_endpoint';
        END IF;
    END IF;

    RETURN NEW;
END;
$body$, '@schema@', quote_ident(schema_name)));
END;
$migration$;

CREATE TRIGGER trust_source_egress_enabled
    BEFORE INSERT OR UPDATE ON trust_source
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_trust_source_egress();
ALTER TABLE trust_source ENABLE ALWAYS TRIGGER trust_source_egress_enabled;
