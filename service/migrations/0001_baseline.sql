-- Baseline: the schema_info marker and the append-only trigger function.
-- Conventions for all migrations are in README.md in this directory.
--
-- The append-only triggers are a tripwire against application DML, not a
-- security boundary: the table owner or a superuser can still disable or
-- drop them, or rewrite rows with ALTER TABLE ... ALTER COLUMN ... TYPE ... USING.
-- ENABLE ALWAYS keeps them firing under session_replication_role = replica.

-- Rejects UPDATE, DELETE and TRUNCATE on the table it is attached to, with
-- the project SQLSTATE SK001.
CREATE FUNCTION skyoauth_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on append-only table % is not allowed', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'SK001';
END;
$$;

-- Identifies the database as a skyoauth schema. Exactly one row.
CREATE TABLE schema_info (
    singleton   boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    product     text        NOT NULL CHECK (product = 'skyoauth'),
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_info (product) VALUES ('skyoauth');

CREATE TRIGGER schema_info_append_only
    BEFORE UPDATE OR DELETE ON schema_info
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_mutation();
ALTER TABLE schema_info ENABLE ALWAYS TRIGGER schema_info_append_only;

CREATE TRIGGER schema_info_no_truncate
    BEFORE TRUNCATE ON schema_info
    FOR EACH STATEMENT EXECUTE FUNCTION skyoauth_reject_mutation();
ALTER TABLE schema_info ENABLE ALWAYS TRIGGER schema_info_no_truncate;
