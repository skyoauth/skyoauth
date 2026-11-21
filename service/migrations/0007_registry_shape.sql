-- Shape changes to the registry tables of 0001 to 0005 (T10.1): a revision
-- on tenants, principals and trust keyset versions, a named range check on
-- every timestamptz column, and an index on the referencing side of the
-- foreign keys that had none (lead decisions, 2026-11-21; README.md "What
-- 0007 adds"). The conventions of 0002 to 0006 apply. "(inferred)" marks a
-- choice the specifications and lead decisions do not dictate. README.md
-- "Follow-ups" listed these items. The earlier migrations stay unchanged;
-- the comments of 0002 and 0004 on revisions describe the schema before
-- 0007.
--
-- Each table's new column and checks are added by one ALTER TABLE
-- statement, so a table is scanned once to validate its new checks. The
-- migration runs in one transaction and holds every lock until it commits
-- (README.md has the measured levels).

-- Revisions, as in 0002 to 0005: a bigint that starts at 1 and advances by
-- exactly 1 on every UPDATE (skyoauth_check_revision() of 0002). Existing
-- rows get 1. The immutable-column guards are unchanged: the selectors,
-- ownership and creation times stay immutable, revision is checked by its
-- own trigger, and a version's status stays mutable. Sources: tasks
-- section 3 "IDs/names" (updates require ID, tenant and revision) and the
-- lead decision of 2026-11-21 (a registry update_trust_keyset_version is a
-- compare-and-set on the version's own revision, not the keyset's).
--
-- Timestamps: every timestamptz column, the 0001 schema_info.created_at
-- included, holds a finite time between -210866803200000000 and
-- i64::MAX - 1 microseconds from the Unix epoch: PostgreSQL's earliest
-- timestamptz (4714-11-24 00:00:00+00 BC) and the latest time the registry
-- reads back exactly, which is also the range it writes (lead decision,
-- 2026-11-21). The lower bound only excludes -infinity, the upper one
-- infinity and the finite times past i64::MAX - 1 microseconds. NULL
-- passes, as for every CHECK. The literals carry an explicit +00 offset,
-- so the bounds do not depend on the session's TimeZone. Each check is
-- named <table>_<column>_range_check and repeats the two literals
-- (inferred: no shared function, so each check reads alone in the
-- catalog). An audit_event row outside the range is an integrity
-- incident, never edited in place: the event hash covers its timestamp
-- (identity-registry IR-056, OQ-IR-15; README.md "What 0007 adds").

ALTER TABLE schema_info
    ADD CONSTRAINT schema_info_created_at_range_check
        CHECK (created_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND created_at <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE tenant
    ADD COLUMN revision bigint NOT NULL DEFAULT 1
        CONSTRAINT tenant_revision_check CHECK (revision >= 1),
    ADD CONSTRAINT tenant_created_at_range_check
        CHECK (created_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND created_at <= timestamptz '294247-01-10 04:00:54.775806+00');

CREATE TRIGGER tenant_revision
    BEFORE INSERT OR UPDATE ON tenant
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE tenant ENABLE ALWAYS TRIGGER tenant_revision;

ALTER TABLE principal
    ADD COLUMN revision bigint NOT NULL DEFAULT 1
        CONSTRAINT principal_revision_check CHECK (revision >= 1),
    ADD CONSTRAINT principal_created_at_range_check
        CHECK (created_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND created_at <= timestamptz '294247-01-10 04:00:54.775806+00');

CREATE TRIGGER principal_revision
    BEFORE INSERT OR UPDATE ON principal
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE principal ENABLE ALWAYS TRIGGER principal_revision;

ALTER TABLE instance_security_policy
    ADD CONSTRAINT instance_security_policy_audit_sink_validated_at_range_check
        CHECK (audit_sink_validated_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND audit_sink_validated_at <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_timestamp_range_check
        CHECK ("timestamp" >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND "timestamp" <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE trust_keyset_version
    ADD COLUMN revision bigint NOT NULL DEFAULT 1
        CONSTRAINT trust_keyset_version_revision_check CHECK (revision >= 1),
    ADD CONSTRAINT trust_keyset_version_effective_at_range_check
        CHECK (effective_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND effective_at <= timestamptz '294247-01-10 04:00:54.775806+00'),
    ADD CONSTRAINT trust_keyset_version_expires_at_range_check
        CHECK (expires_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND expires_at <= timestamptz '294247-01-10 04:00:54.775806+00');

CREATE TRIGGER trust_keyset_version_revision
    BEFORE INSERT OR UPDATE ON trust_keyset_version
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE trust_keyset_version ENABLE ALWAYS TRIGGER trust_keyset_version_revision;

ALTER TABLE service_grant
    ADD CONSTRAINT service_grant_valid_until_range_check
        CHECK (valid_until >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND valid_until <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE admin_identity
    ADD CONSTRAINT admin_identity_created_at_range_check
        CHECK (created_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND created_at <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE admin_credential
    ADD CONSTRAINT admin_credential_revoked_at_range_check
        CHECK (revoked_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND revoked_at <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE administrative_operation
    ADD CONSTRAINT administrative_operation_expires_at_range_check
        CHECK (expires_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND expires_at <= timestamptz '294247-01-10 04:00:54.775806+00'),
    ADD CONSTRAINT administrative_operation_consumed_at_range_check
        CHECK (consumed_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND consumed_at <= timestamptz '294247-01-10 04:00:54.775806+00'),
    ADD CONSTRAINT administrative_operation_revoked_at_range_check
        CHECK (revoked_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND revoked_at <= timestamptz '294247-01-10 04:00:54.775806+00');

ALTER TABLE consumed_assertion
    ADD CONSTRAINT consumed_assertion_consumed_at_range_check
        CHECK (consumed_at >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND consumed_at <= timestamptz '294247-01-10 04:00:54.775806+00'),
    ADD CONSTRAINT consumed_assertion_retain_until_range_check
        CHECK (retain_until >= timestamptz '4714-11-24 00:00:00+00 BC'
            AND retain_until <= timestamptz '294247-01-10 04:00:54.775806+00');

-- Referencing-side indexes: a foreign key whose columns lead no index of
-- the referencing table gets a plain btree index on them, in the key's
-- column order, named <table>_<columns>_idx. With them a parent-scoped
-- lookup, and the foreign-key check of a DELETE or key UPDATE of the
-- referenced row, reads an index instead of the whole referencing table.
-- Since 0006 most referenced rows are never deleted and their keys are
-- immutable, so the checks run for a deleted binding or grant, and when
-- the table owner repairs rows with the guards disabled. Names follow the
-- 0003 and 0004 rules where they would pass the 63-byte limit:
-- resource_server_id becomes server_id, and (inferred) a principal
-- reference's columns, <x>_principal_id with <x>_principal_kind where the
-- key has it, become <x>_principal. The indexes are not partial (inferred:
-- the tables are small, so a partial index would save little).
--
-- Five foreign keys get no index (inferred): the leading column of their
-- table's primary key is one of their columns and identifies the
-- referenced row on its own (a checker, a service identity or a grant ID
-- is unique across tenants), so the primary-key index already narrows the
-- check to that row's few referencing rows. They are
-- resource_server_checker_tenant_checker_fkey,
-- service_identity_resource_server_service_id_fkey,
-- service_grant_binding_grant_id_fkey,
-- service_grant_resource_server_grant_id_fkey and service_identity_id_fkey
-- (whose referencing column id is the primary key itself).

CREATE INDEX audience_tenant_assignment_resource_server_id_idx
    ON audience_tenant_assignment (resource_server_id);

CREATE INDEX resource_server_checker_resource_server_id_idx
    ON resource_server_checker (resource_server_id);

CREATE INDEX resource_server_checker_tenant_tenant_id_resource_server_id_idx
    ON resource_server_checker_tenant (tenant_id, resource_server_id);

CREATE INDEX trust_keyset_version_tenant_id_keyset_id_idx
    ON trust_keyset_version (tenant_id, keyset_id);

CREATE INDEX trust_source_tenant_id_jwks_keyset_id_idx
    ON trust_source (tenant_id, jwks_keyset_id);

CREATE INDEX principal_binding_tenant_id_trust_source_id_idx
    ON principal_binding (tenant_id, trust_source_id);

CREATE INDEX principal_binding_tenant_id_workload_principal_idx
    ON principal_binding (tenant_id, workload_principal_id, workload_principal_kind);

CREATE INDEX service_identity_resource_server_tenant_id_server_id_idx
    ON service_identity_resource_server (tenant_id, resource_server_id);

CREATE INDEX service_grant_tenant_id_target_service_id_idx
    ON service_grant (tenant_id, target_service_id);

CREATE INDEX service_grant_tenant_id_actor_principal_idx
    ON service_grant (tenant_id, actor_principal_id, actor_principal_kind);

CREATE INDEX service_grant_binding_tenant_id_binding_id_actor_principal_idx
    ON service_grant_binding (tenant_id, binding_id, actor_principal_id);

CREATE INDEX service_grant_resource_server_tenant_id_resource_server_id_idx
    ON service_grant_resource_server (tenant_id, resource_server_id);

CREATE INDEX admin_credential_admin_id_idx
    ON admin_credential (admin_id);

CREATE INDEX admin_role_binding_tenant_id_idx
    ON admin_role_binding (tenant_id);

CREATE INDEX administrative_operation_tenant_id_idx
    ON administrative_operation (tenant_id);

CREATE INDEX administrative_operation_revocation_operation_id_idx
    ON administrative_operation (revocation_operation_id);

CREATE INDEX administrative_operation_approves_operation_id_idx
    ON administrative_operation (approves_operation_id);

CREATE INDEX administrative_operation_audit_id_idx
    ON administrative_operation (audit_id);
