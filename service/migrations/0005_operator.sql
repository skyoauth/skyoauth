-- Operator identities, credentials and role bindings, the recovery state,
-- administrative operations and consumed single-use WIF proofs of the M1a
-- domain schema (T10.1), named as in the logical model
-- (docs/skyoauth-tasks.md section 3; design section 7.2; identity-registry
-- section 5.2; ADR-008; ADR-013). The operator tables and the recovery state
-- are instance authority: instance security_admin enrolls operators and
-- scoped roles and manages recovery policy (design section 7.2), and
-- operators are not principals (identity-registry section 5.2), so these
-- tables have no tenant owner. A role binding and an administrative
-- operation may name one tenant, by a plain reference to it, as an
-- audience assignment does in 0003. consumed_assertion is tenant-owned
-- one-time state (T10.9): a composite (tenant_id, trust_source_id) foreign
-- key keeps it on a source of its own tenant (IR-031; tasks section 3
-- "Ownership"). The conventions of 0002 to 0004 apply: README.md in this
-- directory has them and the rules left to the service. "(inferred)" marks
-- a choice the specifications do not dictate.
--
-- Guard triggers raise SK001 (the three AFTER checks at the end
-- of this file: 23514) and are ENABLE ALWAYS, so they also fire under
-- session_replication_role = replica. They keep immutable columns unchanged,
-- keep one-way state one-way, reject an UPDATE consuming a revoked operation,
-- check revisions, and keep consumed proofs unchanged. An INSERT carrying
-- both consumed_at and revoked_at, or one UPDATE setting both, is the service's.
--
-- Every column is NOT NULL unless the logical model marks the field
-- optional. Every foreign key is named, takes no action on delete or update
-- and is not deferrable. status is 'enabled' or 'disabled' everywhere
-- (inferred, as in 0003 and 0004: operators are enrolled and disabled,
-- public-api section 7.1). revision defaults to 1, the only value
-- skyoauth_check_revision() accepts on insert. Delete and truncate guards
-- come with the one follow-up migration for all registry tables (README.md
-- "Follow-ups"); until then only foreign keys hold back a DELETE of these
-- tables, the one-time state included, and no trigger holds back a
-- TRUNCATE: foreign keys refuse only a TRUNCATE that leaves out the
-- referencing tables, and TRUNCATE ... CASCADE includes them (README.md
-- lists what that leaves open).
--
-- Bounds, as in 0003 and 0004 (lead decision, 2026-11-20): every ID column,
-- own ID or reference, is at most 255 bytes, and every exact string at most
-- 2048 bytes, each with a named <table>_<column>_octet_length_check, so an
-- over-long value fails with 23514, also when it names a missing row, never
-- with the btree error 54000. Where the full name would exceed the 63-byte
-- identifier limit, approves_operation_id is abbreviated to approves_id and
-- revocation_operation_id to revocation_id. Names and exact strings that
-- are compared exactly also reject whitespace and control characters
-- (<table>_<column>_no_space_check, evaluated under "C" whatever the
-- collation, as in 0004). Digests are bytea of 32 to 64 bytes (inferred: at
-- least a 256-bit digest, at most a 512-bit one; no source names the
-- algorithm). The other checks of a single column keep the names PostgreSQL
-- generates; the rules that tie several columns together are named.

-- 0005 makes audit_event and instance_security_policy foreign-key targets,
-- and every key column of the schema is bounded (lead decision,
-- 2026-11-20), so the remaining unbounded key columns of 0002 get named
-- 255-byte bounds here, as principal's did in 0004: the key of each foreign
-- key target, audit_event.tenant_id and the egress entry ID. 0005 leaves the
-- 0002 file unchanged. The checks validate existing rows; README.md has the
-- upgrade precondition.
ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_id_octet_length_check CHECK (octet_length(id) <= 255),
    ADD CONSTRAINT audit_event_tenant_id_octet_length_check CHECK (octet_length(tenant_id) <= 255);
ALTER TABLE instance_security_policy
    ADD CONSTRAINT instance_security_policy_instance_id_octet_length_check
    CHECK (octet_length(instance_id) <= 255);
ALTER TABLE egress_allowlist_entry
    ADD CONSTRAINT egress_allowlist_entry_id_octet_length_check CHECK (octet_length(id) <= 255);

-- Rejects an UPDATE that changes a named column once it is set: once it is
-- not NULL and, for a boolean, true. So a timestamp or reference is set
-- once and never cleared or changed, and a boolean goes from false to true
-- only. As for skyoauth_reject_immutable_change(), an argument that names
-- no column of the table is an error, so a typo cannot silently disable the
-- guard. It resolves no table, so it pins only pg_catalog and pg_temp.
CREATE FUNCTION skyoauth_reject_change_once_set() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    old_row jsonb := to_jsonb(OLD);
    new_row jsonb := to_jsonb(NEW);
    col text;
BEGIN
    FOREACH col IN ARRAY TG_ARGV LOOP
        IF NOT old_row ? col THEN
            RAISE EXCEPTION 'set-once guard on % names unknown column %',
                TG_TABLE_NAME, col;
        END IF;
        IF old_row -> col NOT IN ('null'::jsonb, 'false'::jsonb)
            AND old_row -> col IS DISTINCT FROM new_row -> col THEN
            RAISE EXCEPTION 'column %.% cannot change once set', TG_TABLE_NAME, col
                USING ERRCODE = 'SK001';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

-- AdminIdentity: an independent adm_* operator identity (design section
-- 7.2; identity-registry section 5.2). Enrolled and disabled by instance
-- security_admin (public-api section 7.1, /admin/v1/operators).
CREATE TABLE admin_identity (
    id          text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT admin_identity_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    status      text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- AdminCredential: a registered mTLS public credential of an operator,
-- rooted in deployment trust (design section 7.2; T13.1).
CREATE TABLE admin_credential (
    id                text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT admin_credential_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    admin_id          text COLLATE "C" NOT NULL
        CONSTRAINT admin_credential_admin_id_octet_length_check
        CHECK (octet_length(admin_id) <= 255)
        CONSTRAINT admin_credential_admin_id_fkey REFERENCES admin_identity (id),
    -- The canonical public-key identity of the mTLS credential, for example
    -- the SHA-256 digest of its SubjectPublicKeyInfo, which the service
    -- computes and canonicalizes. Subject DNs are not stored here: a DN names
    -- a certificate's subject, not a key. Only its length is bounded, as for
    -- resource_server_checker.public_mtls_identity in 0003. It is registered
    -- at most once, revoked credentials included, so a revoked key can never
    -- be registered again while its row exists (inferred; README.md
    -- "Follow-ups" has the delete guard that keeps the row).
    public_identity   text COLLATE "C" NOT NULL UNIQUE CHECK (public_identity <> '')
        CONSTRAINT admin_credential_public_identity_octet_length_check
        CHECK (octet_length(public_identity) <= 2048),
    -- The deployment trust anchor the credential is rooted in (design
    -- section 7.2). Its syntax is not specified; it is an exact reference to
    -- deployment configuration, bounded and cleaned as the secret references
    -- of 0004 (inferred).
    trust_anchor_ref  text COLLATE "C" NOT NULL CHECK (trust_anchor_ref <> '')
        CONSTRAINT admin_credential_trust_anchor_ref_no_space_check
        CHECK ((trust_anchor_ref COLLATE "C") !~ '[[:space:][:cntrl:]]')
        CONSTRAINT admin_credential_trust_anchor_ref_octet_length_check
        CHECK (octet_length(trust_anchor_ref) <= 2048),
    status            text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revoked_at        timestamptz,
    -- Revocation is permanent disablement (inferred): a revoked credential
    -- stays disabled, since revoked_at is set once (trigger below).
    CONSTRAINT admin_credential_revoked_disabled_check
        CHECK (revoked_at IS NULL OR status = 'disabled')
);

-- AdminRoleBinding: one explicit role assignment (design section 7.2;
-- T13.2). Roles do not inherit one another (public-api API-120).
-- security_admin is an instance role and trust_admin, client_admin and
-- provider_admin are tenant roles (identity-registry section 5.2), so
-- tenant_id is NULL for security_admin and set for those three. auditor is
-- a tenant or an instance role: an instance-scoped auditor assignment
-- (tenant_id NULL) is the only grant of instance audit reads (ADR-013
-- OQ-ADR013-3).
CREATE TABLE admin_role_binding (
    id         text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT admin_role_binding_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    admin_id   text COLLATE "C" NOT NULL
        CONSTRAINT admin_role_binding_admin_id_octet_length_check
        CHECK (octet_length(admin_id) <= 255)
        CONSTRAINT admin_role_binding_admin_id_fkey REFERENCES admin_identity (id),
    role       text COLLATE "C" NOT NULL
        CHECK (role IN ('security_admin', 'trust_admin', 'client_admin', 'provider_admin',
                        'auditor')),
    tenant_id  text COLLATE "C"
        CONSTRAINT admin_role_binding_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT admin_role_binding_tenant_id_fkey REFERENCES tenant (id),
    status     text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision   bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    CONSTRAINT admin_role_binding_scope_check
        CHECK (role = 'auditor' OR (tenant_id IS NULL) = (role = 'security_admin')),
    -- One binding per operator, role and tenant, disabled rows included, so
    -- a role is re-enabled rather than assigned twice (inferred). NULLS NOT
    -- DISTINCT makes this hold for security_admin too.
    UNIQUE NULLS NOT DISTINCT (admin_id, role, tenant_id)
);

-- RecoveryState: one row per instance (tasks section 3; ADR-013 item 8 and
-- OQ-ADR013-1). The bootstrap transaction inserts it with the first
-- security_admin credential and the offline recovery public key and closes
-- bootstrap (design section 7.2; T13.4); the schema allows at most one row,
-- so a concurrent second bootstrap fails with 23505 (T13.6).
CREATE TABLE recovery_state (
    -- The instance_id of the instance_security_policy row (inferred; IR-057
    -- generates it at first bootstrap and stores it there).
    instance_id          text COLLATE "C" PRIMARY KEY CHECK (instance_id <> '')
        CONSTRAINT recovery_state_instance_id_octet_length_check
        CHECK (octet_length(instance_id) <= 255)
        CONSTRAINT recovery_state_instance_id_fkey
        REFERENCES instance_security_policy (instance_id),
    -- Restart or an empty configuration cannot reopen bootstrap (design
    -- section 7.2; T13.4): false to true only (trigger below). No default:
    -- the service states it (inferred).
    bootstrap_closed     boolean     NOT NULL,
    -- The current offline recovery public key. Its encoding is the
    -- service's (inferred: bytes, non-empty, at most 8192 bytes, room for a
    -- post-quantum key).
    recovery_public_key  bytea       NOT NULL
        CONSTRAINT recovery_state_recovery_public_key_octet_length_check
        CHECK (octet_length(recovery_public_key) BETWEEN 1 AND 8192),
    -- Advanced with every key rotation (OQ-TM-8; trigger below); the first
    -- key is epoch 1 (inferred).
    recovery_key_epoch   bigint      NOT NULL CHECK (recovery_key_epoch >= 1),
    revision             bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

CREATE UNIQUE INDEX recovery_state_single_row ON recovery_state ((true));

-- The recovery key is replaced only by rotation (design section 7.2;
-- OQ-TM-8, OQ-TM-15): recovery_key_epoch never decreases, and it increases
-- exactly when recovery_public_key changes (inferred: a rotation enrolls a
-- new key and an epoch without a new key means nothing). The database holds
-- only the current key, so it cannot refuse a retired key; the service
-- does.
CREATE FUNCTION skyoauth_check_recovery_key_rotation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    IF NEW.recovery_key_epoch < OLD.recovery_key_epoch THEN
        RAISE EXCEPTION 'recovery_key_epoch cannot decrease from % to %',
            OLD.recovery_key_epoch, NEW.recovery_key_epoch
            USING ERRCODE = 'SK001';
    END IF;
    IF (NEW.recovery_public_key IS DISTINCT FROM OLD.recovery_public_key)
        IS DISTINCT FROM (NEW.recovery_key_epoch > OLD.recovery_key_epoch) THEN
        RAISE EXCEPTION 'recovery_key_epoch advances exactly when recovery_public_key changes'
            USING ERRCODE = 'SK001';
    END IF;
    RETURN NEW;
END;
$$;

-- AdministrativeOperation (tasks section 3; ADR-008 item 12; IR-054;
-- public-api section 7.1): an operator write, a pending gated write, an
-- approval, a route-bundle or credential operation, or a recovery challenge.
-- tenant_id is NULL for an instance operation.
CREATE TABLE administrative_operation (
    id                       text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT administrative_operation_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id                text COLLATE "C"
        CONSTRAINT administrative_operation_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT administrative_operation_tenant_id_fkey REFERENCES tenant (id),
    -- Not a foreign key to admin_identity (inferred): bootstrap and
    -- break-glass recovery act for the deployment operator and the offline
    -- recovery key holder, which are not operator identities (design
    -- section 7.2). The service resolves the actor.
    actor_id                 text COLLATE "C" NOT NULL CHECK (actor_id <> '')
        CONSTRAINT administrative_operation_actor_id_octet_length_check
        CHECK (octet_length(actor_id) <= 255),
    -- The operation kind. The sources name kinds (approve,
    -- route_bundle_prepare, route_bundle_approval, credential_retirement,
    -- among others) but no closed set, so it is a bounded name (inferred,
    -- as resource_action.action_name in 0003).
    kind                     text COLLATE "C" NOT NULL CHECK (kind <> '')
        CONSTRAINT administrative_operation_kind_no_space_check
        CHECK ((kind COLLATE "C") !~ '[[:space:][:cntrl:]]')
        CONSTRAINT administrative_operation_kind_octet_length_check
        CHECK (octet_length(kind) <= 2048),
    -- The digest an approver echoes (public-api OQ-API-13).
    request_digest           bytea       NOT NULL
        CONSTRAINT administrative_operation_request_digest_octet_length_check
        CHECK (octet_length(request_digest) BETWEEN 32 AND 64),
    -- The expected revision of the object the operation writes; 0 when it
    -- creates the object (inferred: revisions start at 1).
    expected_revision        bigint      NOT NULL CHECK (expected_revision >= 0),
    -- No shape is specified (inferred: a JSON object).
    immutable_plan           jsonb       NOT NULL CHECK (jsonb_typeof(immutable_plan) = 'object'),
    -- The hash of a break-glass recovery challenge (design section 7.2;
    -- T13.5); the service computes it.
    challenge_hash           bytea
        CONSTRAINT administrative_operation_challenge_hash_octet_length_check
        CHECK (octet_length(challenge_hash) BETWEEN 32 AND 64),
    expires_at               timestamptz,
    consumed_at              timestamptz,
    revoked_at               timestamptz,
    revocation_operation_id  text COLLATE "C"
        CONSTRAINT administrative_operation_revocation_id_octet_length_check
        CHECK (octet_length(revocation_operation_id) <= 255)
        CONSTRAINT administrative_operation_revocation_operation_id_fkey
        REFERENCES administrative_operation (id),
    approves_operation_id    text COLLATE "C"
        CONSTRAINT administrative_operation_approves_id_octet_length_check
        CHECK (octet_length(approves_operation_id) <= 255)
        CONSTRAINT administrative_operation_approves_operation_id_fkey
        REFERENCES administrative_operation (id),
    revision                 bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    -- No value set is specified (inferred: non-empty text in the database
    -- collation, as audit_event.outcome in 0002).
    outcome                  text        NOT NULL CHECK (outcome <> ''),
    -- The audit event that records the operation (inferred), of the
    -- operation's tenant (guard below). audit_event is append-only, so the
    -- reference never dangles; the event is inserted first (README.md).
    audit_id                 text COLLATE "C" NOT NULL
        CONSTRAINT administrative_operation_audit_id_octet_length_check
        CHECK (octet_length(audit_id) <= 255)
        CONSTRAINT administrative_operation_audit_id_fkey REFERENCES audit_event (id),
    -- An approval (kind approve) names the operation it approves (IR-054).
    -- Other kinds may name one too, of their own tenant (guard below): a
    -- route_bundle_approval names its preparation (tasks section 3 "Route
    -- preparation, approval and recovery").
    CONSTRAINT administrative_operation_approve_kind_check
        CHECK (kind <> 'approve' OR approves_operation_id IS NOT NULL),
    -- No operation approves or revokes itself (inferred).
    CONSTRAINT administrative_operation_approves_self_check
        CHECK (approves_operation_id <> id),
    CONSTRAINT administrative_operation_revokes_self_check
        CHECK (revocation_operation_id <> id),
    -- revoked_at and revocation_operation_id are recorded together (design
    -- section 4.2; tasks section 3 "Route preparation, approval and
    -- recovery").
    CONSTRAINT administrative_operation_revocation_check
        CHECK ((revoked_at IS NULL) = (revocation_operation_id IS NULL)),
    -- A recovery challenge expires (LT-107).
    CONSTRAINT administrative_operation_challenge_expiry_check
        CHECK (challenge_hash IS NULL OR expires_at IS NOT NULL),
    -- An expired operation or challenge is never consumed (LT-107;
    -- public-api OQ-API-13: pending operations are single-use and expire).
    -- An operation may be both consumed and revoked: security_admin revokes
    -- a route_bundle_approval after begin has consumed it (tasks section 3
    -- "Route preparation, approval and recovery"). The set-once guard below
    -- keeps each of the two one-way, and the consume-after-revoke guard
    -- below keeps an UPDATE from consuming an operation already revoked.
    CONSTRAINT administrative_operation_consumed_before_expiry_check
        CHECK (consumed_at < expires_at)
);

-- Rejects an UPDATE that consumes an operation already revoked (lead
-- decision, 2026-11-21): OLD.revoked_at is set, OLD.consumed_at is not, and
-- NEW.consumed_at is. An ON CONFLICT ... DO UPDATE is an UPDATE too.
-- Consumption followed by revocation stays allowed, and so do an UPDATE
-- that leaves consumed_at unset and one that sets both columns of an
-- unconsumed, unrevoked row at once. Only UPDATE is guarded: an INSERT may
-- carry both timestamps, and the database does not compare them; the
-- service must not record, by an INSERT or by one UPDATE that sets both, an
-- operation consumed after its revocation (README.md). It reads no table,
-- so it pins only pg_catalog and pg_temp.
CREATE FUNCTION skyoauth_reject_consume_after_revoke() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND OLD.consumed_at IS NULL
        AND NEW.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'column %.consumed_at cannot be set on revoked row %', TG_TABLE_NAME, OLD.id
            USING ERRCODE = 'SK001';
    END IF;
    RETURN NEW;
END;
$$;

-- ConsumedAssertion: the durable replay record of single-use WIF proofs
-- (T10.9; ADR-016 items 6 and 7; design section 5.3). The service inserts
-- a row for a consumed proof under the current digest-key version, keyed by
-- a keyed digest of (tenant, source_id, exact_issuer, verified_jti), and,
-- during a digest-key cutover, also under the retiring version until that
-- version's drain deadline, so replay detection spans digest-key rotation
-- (README.md has the drain protocol); the primary key makes
-- consumption atomic across replicas and grants: a replay fails with 23505
-- (or inserts nothing under ON CONFLICT DO NOTHING). Rows are never updated
-- (trigger below); deleting a row after retain_until is the only intended
-- removal, a service or job rule until the delete-guard migration
-- (README.md).
CREATE TABLE consumed_assertion (
    tenant_id           text COLLATE "C"
        CONSTRAINT consumed_assertion_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255),
    trust_source_id     text COLLATE "C"
        CONSTRAINT consumed_assertion_trust_source_id_octet_length_check
        CHECK (octet_length(trust_source_id) <= 255),
    replay_key_digest   bytea
        CONSTRAINT consumed_assertion_replay_key_digest_octet_length_check
        CHECK (octet_length(replay_key_digest) BETWEEN 32 AND 64),
    -- The version of the digest key (retention spans digest-key rotation,
    -- ADR-016 item 7); an opaque identifier (inferred).
    digest_key_version  text COLLATE "C" NOT NULL CHECK (digest_key_version <> '')
        CONSTRAINT consumed_assertion_digest_key_version_octet_length_check
        CHECK (octet_length(digest_key_version) <= 255),
    consumed_at         timestamptz NOT NULL,
    -- Through proof exp plus skew (lifetimes section 9); the service
    -- computes it.
    retain_until        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, trust_source_id, replay_key_digest),
    CONSTRAINT consumed_assertion_trust_source_id_fkey
        FOREIGN KEY (tenant_id, trust_source_id) REFERENCES trust_source (tenant_id, id),
    -- A retention window is not empty (inferred).
    CONSTRAINT consumed_assertion_retention_check CHECK (retain_until > consumed_at)
);

-- Immutable columns. IDs are immutable selectors (tasks section 3
-- "IDs/names"); an operation's plan, digest, kind and actor are immutable
-- (tasks section 3 "Route preparation, approval and recovery": the
-- immutable_plan is never changed, even by revocation). Inferred: an
-- identity's created_at (as for tenant in 0002); every column of a
-- credential but status and revoked_at (a new key is a new credential);
-- every column of a role binding but status and revision; the recovery
-- state's instance_id; and an operation's tenant, expected revision,
-- challenge, expiry, approved operation and audit event.
CREATE TRIGGER admin_identity_immutable
    BEFORE UPDATE ON admin_identity
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('id', 'created_at');
ALTER TABLE admin_identity ENABLE ALWAYS TRIGGER admin_identity_immutable;

CREATE TRIGGER admin_credential_immutable
    BEFORE UPDATE ON admin_credential
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'admin_id', 'public_identity', 'trust_anchor_ref');
ALTER TABLE admin_credential ENABLE ALWAYS TRIGGER admin_credential_immutable;

CREATE TRIGGER admin_role_binding_immutable
    BEFORE UPDATE ON admin_role_binding
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'admin_id', 'role', 'tenant_id');
ALTER TABLE admin_role_binding ENABLE ALWAYS TRIGGER admin_role_binding_immutable;

CREATE TRIGGER recovery_state_immutable
    BEFORE UPDATE ON recovery_state
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('instance_id');
ALTER TABLE recovery_state ENABLE ALWAYS TRIGGER recovery_state_immutable;

CREATE TRIGGER administrative_operation_immutable
    BEFORE UPDATE ON administrative_operation
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'tenant_id', 'actor_id', 'kind', 'request_digest',
            'expected_revision', 'immutable_plan', 'challenge_hash', 'expires_at',
            'approves_operation_id', 'audit_id');
ALTER TABLE administrative_operation ENABLE ALWAYS TRIGGER administrative_operation_immutable;

-- One-way state. A credential's revocation (T13.5, T13.6), an operation's
-- consumption (one-time, LT-107; public-api OQ-API-13) and its revocation
-- with the revoking operation (monotonic, tasks section 3) are set once and
-- never cleared or changed; bootstrap_closed goes from false to true only
-- (T13.4).
CREATE TRIGGER admin_credential_set_once
    BEFORE UPDATE ON admin_credential
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_change_once_set('revoked_at');
ALTER TABLE admin_credential ENABLE ALWAYS TRIGGER admin_credential_set_once;

CREATE TRIGGER recovery_state_set_once
    BEFORE UPDATE ON recovery_state
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_change_once_set('bootstrap_closed');
ALTER TABLE recovery_state ENABLE ALWAYS TRIGGER recovery_state_set_once;

CREATE TRIGGER recovery_state_key_rotation
    BEFORE UPDATE ON recovery_state
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_recovery_key_rotation();
ALTER TABLE recovery_state ENABLE ALWAYS TRIGGER recovery_state_key_rotation;

CREATE TRIGGER administrative_operation_set_once
    BEFORE UPDATE ON administrative_operation
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_change_once_set('consumed_at', 'revoked_at', 'revocation_operation_id');
ALTER TABLE administrative_operation ENABLE ALWAYS TRIGGER administrative_operation_set_once;

-- A revoked operation is not consumed afterwards; a consumed one may still
-- be revoked (function above).
CREATE TRIGGER administrative_operation_no_consume_after_revoke
    BEFORE UPDATE ON administrative_operation
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_consume_after_revoke();
ALTER TABLE administrative_operation ENABLE ALWAYS TRIGGER administrative_operation_no_consume_after_revoke;

-- A consumed proof is a fact: no column of the row ever changes, so an
-- UPDATE, an ON CONFLICT DO UPDATE included, is rejected (SK001).
CREATE TRIGGER consumed_assertion_no_update
    BEFORE UPDATE ON consumed_assertion
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_mutation();
ALTER TABLE consumed_assertion ENABLE ALWAYS TRIGGER consumed_assertion_no_update;

CREATE TRIGGER admin_role_binding_revision
    BEFORE INSERT OR UPDATE ON admin_role_binding
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE admin_role_binding ENABLE ALWAYS TRIGGER admin_role_binding_revision;

CREATE TRIGGER recovery_state_revision
    BEFORE INSERT OR UPDATE ON recovery_state
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE recovery_state ENABLE ALWAYS TRIGGER recovery_state_revision;

CREATE TRIGGER administrative_operation_revision
    BEFORE INSERT OR UPDATE ON administrative_operation
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE administrative_operation ENABLE ALWAYS TRIGGER administrative_operation_revision;

-- The approval, audit and revocation guards (IR-054;
-- docs/proposals/second-approver-gated-writes.md section 11 and D15). The
-- review of 0005 first left these rules to the service; on 2026-11-23
-- the user accepted a database tripwire for the approval and revocation
-- rules, and on 2026-11-24 for the two cross-scope references the first
-- guards left open (the audit event of an operation, and the approved
-- operation of a kind other than 'approve'), each folded into 0005 in
-- place under the pre-beta exception (README.md "Conventions"; rulings
-- relayed by the lead; provisional until the maintainer ratifies the ADRs,
-- T00.8 to T00.17, Gate M0). A database created from an earlier 0005 is
-- recreated. README.md "What 0005 adds" has the details; "(inferred)"
-- marks a choice the proposal and the rulings do not dictate.
--
-- An operation that names an approved operation (approves_operation_id),
-- of any kind, names an operation of its own tenant, IS NOT DISTINCT FROM,
-- so an instance operation (tenant_id NULL) names an instance operation:
-- no source makes a reference to another scope legitimate (README.md). An
-- operation of kind 'approve' is also never by the approved operation's
-- actor. Only kind 'approve': a route_bundle_approval also names its
-- preparation, and one person MAY hold both roles there (IR-054; GW-130,
-- GW-131), so its actor is not checked. Every operation names an audit
-- event (audit_id) of its own tenant, compared the same way, so an
-- instance operation names an instance event (tenant_id NULL) and a tenant
-- operation an event of that tenant. A revocation (a cancel or a reject)
-- names a revoking operation of the revoked row's tenant, checked where the
-- link is written, on the revoked row: on INSERT too, since 0005 lets an
-- insert carry a revocation, and on an UPDATE that names
-- revocation_operation_id. tenant_id, approves_operation_id and audit_id
-- never change (administrative_operation_immutable above), so the approval
-- and audit checks run on INSERT only. A refusal is check_violation (23514)
-- naming administrative_operation_approves_same_tenant,
-- administrative_operation_approver_distinct,
-- administrative_operation_audit_same_tenant or
-- administrative_operation_revokes_same_tenant (not catalog constraints;
-- the registry lists them in KNOWN_CONSTRAINTS). The message names the
-- table, never a value. The approved operation's tenant is compared first,
-- then its actor (inferred). Nothing else is checked: roles, the digest,
-- the state of the approved operation and the kind of the revoking one
-- stay service rules, and the audit event's action, object and actor are
-- not compared with the operation.
--
-- The triggers are plain (non-deferrable) AFTER ... FOR EACH ROW triggers, as
-- those of 0010 and 0011: they fire at the end of the statement, row by row,
-- after every CHECK, NOT NULL and unique constraint and after that row's
-- foreign-key checks, whose internal triggers (RI_ConstraintTrigger_c_*)
-- sort, and so fire, before administrative_operation_approval_check,
-- administrative_operation_audit_check and
-- administrative_operation_revocation_check, which fire in that order. So a
-- missing approved or revoking operation or audit event is still the foreign
-- key's 23503, and the guard reads the referenced row only once it is known
-- to exist; in a multi-row INSERT an earlier row's 23514 precedes a later
-- row's 23503. The names must keep sorting after "RI_". The guard finds no
-- row only where the foreign keys do not fire (session_replication_role =
-- replica) and then passes the row (inferred, as 0010 does).
--
-- The guards read the referenced row without a row lock (inferred): an
-- operation's tenant_id and actor_id are immutable
-- (administrative_operation_immutable above) and its deletes are refused
-- (0006); an audit event is append-only (0002 refuses its UPDATE, DELETE
-- and TRUNCATE); and the foreign-key check already holds the row
-- FOR KEY SHARE, so no concurrent write can change what they read. Taking
-- no lock also keeps an approve from waiting for the FOR NO KEY UPDATE lock
-- that an approver or a canceller holds on the pending row, and the audit
-- check reads neither audit_chain_head nor anything else, so the guards add
-- no step to the lock order of README.md (the rows a write needs, then the
-- audit head and the event, then the operation, then the remaining
-- updates): they run inside the operation's INSERT or the revocation's
-- UPDATE and wait for nothing.
--
-- The functions read administrative_operation or audit_event, so they are
-- created as the table readers of 0010 and 0011 are: the schema is
-- resolved by current_schema() at migrate time, the table is named with
-- that schema and the body is passed as a quoted literal (%L). Their
-- search_path is pinned to pg_catalog, pg_temp (they resolve no
-- unqualified table). They are SECURITY INVOKER: a role that inserts an
-- operation needs SELECT on audit_event, and one that names an approved
-- operation or writes a revocation needs SELECT on
-- administrative_operation (README.md "What 0005 adds", "Privileges").
DO $migration$
DECLARE
    schema_name constant text := current_schema();
BEGIN
    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS %L', 'skyoauth_check_operation_approval',
        replace($body$
DECLARE
    approved_tenant text COLLATE "C";
    approved_actor text COLLATE "C";
BEGIN
    SELECT o.tenant_id, o.actor_id INTO approved_tenant, approved_actor
        FROM @schema@.administrative_operation o
        WHERE o.id = NEW.approves_operation_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF approved_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'an operation in % approves an operation of another tenant', TG_TABLE_NAME
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'administrative_operation_approves_same_tenant',
                  SCHEMA = TG_TABLE_SCHEMA, TABLE = TG_TABLE_NAME,
                  COLUMN = 'approves_operation_id';
    END IF;
    IF NEW.kind = 'approve' AND approved_actor IS NOT DISTINCT FROM NEW.actor_id THEN
        RAISE EXCEPTION 'an approve in % is by the actor of the operation it approves', TG_TABLE_NAME
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'administrative_operation_approver_distinct',
                  SCHEMA = TG_TABLE_SCHEMA, TABLE = TG_TABLE_NAME,
                  COLUMN = 'actor_id';
    END IF;
    RETURN NULL;
END;
$body$, '@schema@', quote_ident(schema_name)));

    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS %L', 'skyoauth_check_operation_audit_event',
        replace($body$
DECLARE
    event_tenant text COLLATE "C";
BEGIN
    SELECT e.tenant_id INTO event_tenant
        FROM @schema@.audit_event e
        WHERE e.id = NEW.audit_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF event_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'an operation in % names an audit event of another tenant', TG_TABLE_NAME
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'administrative_operation_audit_same_tenant',
                  SCHEMA = TG_TABLE_SCHEMA, TABLE = TG_TABLE_NAME,
                  COLUMN = 'audit_id';
    END IF;
    RETURN NULL;
END;
$body$, '@schema@', quote_ident(schema_name)));

    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS %L', 'skyoauth_check_operation_revocation',
        replace($body$
DECLARE
    revoking_tenant text COLLATE "C";
BEGIN
    SELECT o.tenant_id INTO revoking_tenant
        FROM @schema@.administrative_operation o
        WHERE o.id = NEW.revocation_operation_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF revoking_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'a revocation in % names an operation of another tenant', TG_TABLE_NAME
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'administrative_operation_revokes_same_tenant',
                  SCHEMA = TG_TABLE_SCHEMA, TABLE = TG_TABLE_NAME,
                  COLUMN = 'revocation_operation_id';
    END IF;
    RETURN NULL;
END;
$body$, '@schema@', quote_ident(schema_name)));
END;
$migration$;

CREATE TRIGGER administrative_operation_approval_check
    AFTER INSERT ON administrative_operation
    FOR EACH ROW WHEN (NEW.approves_operation_id IS NOT NULL)
    EXECUTE FUNCTION skyoauth_check_operation_approval();
ALTER TABLE administrative_operation
    ENABLE ALWAYS TRIGGER administrative_operation_approval_check;

CREATE TRIGGER administrative_operation_audit_check
    AFTER INSERT ON administrative_operation
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_operation_audit_event();
ALTER TABLE administrative_operation
    ENABLE ALWAYS TRIGGER administrative_operation_audit_check;

CREATE TRIGGER administrative_operation_revocation_check
    AFTER INSERT OR UPDATE OF revocation_operation_id ON administrative_operation
    FOR EACH ROW WHEN (NEW.revocation_operation_id IS NOT NULL)
    EXECUTE FUNCTION skyoauth_check_operation_revocation();
ALTER TABLE administrative_operation
    ENABLE ALWAYS TRIGGER administrative_operation_revocation_check;

-- The approver's read path (OQ-API-14; the proposal's D22): the open
-- operations of a tenant, by ID. Rows without an expiry (approve, cancel,
-- reject) are never open. A provisional lead pick, 2026-11-23 (inferred),
-- not ruled: it was part of the same sketch as the guards. The read query
-- adds expires_at > now and the approvable kinds, and reads the instance
-- with a second statement, tenant_id IS NULL.
CREATE INDEX administrative_operation_open_by_tenant
    ON administrative_operation (tenant_id, id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at IS NOT NULL;
