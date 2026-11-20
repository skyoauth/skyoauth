-- Resource servers, tenant audience assignments, checker identities and
-- action rules of the M1a domain schema (T10.1), named as in the logical
-- model (docs/skyoauth-tasks.md section 3; identity-registry section 7;
-- ADR-018). All four are instance authority (tasks section 3 "Ownership");
-- an assignment grants one named tenant bounded issuance rights. The
-- conventions of 0002 apply: README.md in this directory has them and the
-- rules left to the service. "(inferred)" marks a choice the specifications
-- do not dictate.
--
-- status is 'enabled' or 'disabled' everywhere (inferred): the sources speak
-- of disabling and re-enabling resource servers and assignments (ADR-018
-- items 4 and 6) and of an "active" assignment (IR-080), read as enabled.
-- Rows are disabled, not deleted (no DELETE endpoint, public-api section 7).
-- Delete and truncate guards for all registry tables come in one later
-- migration, decided together (lead decision, 2026-11-20; README.md
-- "Follow-ups"); until then only foreign keys hold back a delete.

-- The list-valued columns are jsonb arrays. Their shape is checked through
-- domains, so each rule is written once; a domain CHECK is stored as an
-- expression tree, so it resolves no names through the caller's
-- search_path. jsonb_path_exists runs in strict mode, so a nested array is
-- one element, not unwrapped, and silently, so a non-array gives NULL and
-- fails the jsonb_typeof test.

-- Scope tokens (IR-066, RFC 6749 section 3.3 scope-token):
-- 1*( %x21 / %x23-5B / %x5D-7E ). The bracket expression lists ], !, #-[
-- and ^-~. Duplicates are not rejected (inferred: no source says a stored
-- ceiling is duplicate-free).
CREATE DOMAIN skyoauth_scope_list AS jsonb
    CHECK (jsonb_typeof(VALUE) = 'array' AND NOT jsonb_path_exists(VALUE,
        'strict $[*] ? (@.type() != "string" || !(@ like_regex "^[]!#-[^-~]+$"))',
        '{}', true));

-- Credential profiles (token-profiles section 3: skyoauth_profile).
CREATE DOMAIN skyoauth_profile_list AS jsonb
    CHECK (jsonb_typeof(VALUE) = 'array' AND NOT jsonb_path_exists(VALUE,
        'strict $[*] ? (@.type() != "string"
            || (@ != "wif" && @ != "human_cli" && @ != "human_session"))',
        '{}', true));

-- Names with no specified syntax: non-empty strings (inferred).
CREATE DOMAIN skyoauth_string_list AS jsonb
    CHECK (jsonb_typeof(VALUE) = 'array' AND NOT jsonb_path_exists(VALUE,
        'strict $[*] ? (@.type() != "string" || @ == "")', '{}', true));

-- Unique free-text keys are bounded and cleaned as
-- egress_allowlist_entry.exact_destination is in 0002 (lead decision,
-- 2026-11-20): at most 2048 bytes, well below the btree limit of the unique
-- index, and, where the value is a name, no whitespace or control character
-- ([:space:] is ASCII whitespace under "C"; [:cntrl:] is U+0000-U+001F and
-- U+007F-U+009F in every collation). Other syntax and Unicode normalization
-- stay with the service. Every ID column, own ID or reference, is at most
-- 255 bytes: resource_server.id and tenant.id (lead decision, 2026-11-20),
-- and every other ID and reference column (inferred, as a consequence: an
-- over-long ID would fail with the btree error 54000 on its key's index, and
-- so would an over-long reference naming a missing row, since a CHECK runs
-- before the row enters any index but the foreign key check runs after it).
-- Each composite key then stays below the btree limit of about 2700 bytes
-- even when the values do not compress, and an over-long value fails with
-- 23514. These checks are named, so the service can tell them apart
-- (README.md).

-- A forward-only bound on a 0002 table (lead decision, 2026-11-20): 0002 is
-- frozen, so 0003 adds it. It is validated against existing rows (no NOT
-- VALID).
ALTER TABLE tenant ADD CONSTRAINT tenant_id_octet_length_check
    CHECK (octet_length(id) <= 255);

-- ResourceServer (IR-070, IR-071). The audience is globally unique and exact
-- (IR-070); that it never changes is (inferred). Its syntax and comparison
-- rules are open (OQ-IR-9), so the database compares it byte-wise.
CREATE TABLE resource_server (
    id                   text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT resource_server_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    audience             text COLLATE "C" NOT NULL UNIQUE CHECK (audience <> '')
        CONSTRAINT resource_server_audience_no_space_check
        CHECK (audience !~ '[[:space:][:cntrl:]]')
        CONSTRAINT resource_server_audience_octet_length_check
        CHECK (octet_length(audience) <= 2048),
    name                 text        NOT NULL CHECK (name <> ''),
    allowed_profiles     skyoauth_profile_list NOT NULL,
    scopes               skyoauth_scope_list   NOT NULL,
    -- Versions of the per-resource-server constraint schema (IR-141). Their
    -- type and relation to the constraints "version" member are open
    -- (OQ-TP-7), so only the array shape is checked (inferred).
    constraint_versions  jsonb       NOT NULL CHECK (jsonb_typeof(constraint_versions) = 'array'),
    status               text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision             bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

-- AudienceTenantAssignment (IR-080..IR-083; ADR-018 items 3 and 4). One
-- assignment per resource server and tenant (inferred: ADR-018 item 6 ties a
-- tenant's checker eligibility to "the" assignment's status, and IR-062
-- reads one assignment ceiling per credential). The unique pair is also the
-- target of composite references from tenant-owned records that name an
-- audience (grants, services, clients, origins, human policies; IR-080), so
-- a tenant can only reference an audience assigned to it, and of checker
-- tenant rows.
CREATE TABLE audience_tenant_assignment (
    id                   text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT audience_tenant_assignment_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    -- The name abbreviates resource_server_id: the full one would exceed the
    -- 63-byte identifier limit.
    resource_server_id   text COLLATE "C" NOT NULL
        CONSTRAINT audience_tenant_assignment_server_id_octet_length_check
        CHECK (octet_length(resource_server_id) <= 255)
        CONSTRAINT audience_tenant_assignment_resource_server_id_fkey
        REFERENCES resource_server (id),
    tenant_id            text COLLATE "C" NOT NULL
        CONSTRAINT audience_tenant_assignment_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT audience_tenant_assignment_tenant_id_fkey REFERENCES tenant (id),
    allowed_profiles     skyoauth_profile_list NOT NULL,
    allowed_scopes       skyoauth_scope_list   NOT NULL,
    -- As resource_server.constraint_versions (inferred).
    constraint_versions  jsonb       NOT NULL CHECK (jsonb_typeof(constraint_versions) = 'array'),
    status               text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision             bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    UNIQUE (tenant_id, resource_server_id)
);

-- ResourceServerChecker (IR-090; ADR-018 item 6): a receiver identity, not
-- a principal or ServiceIdentity, so no principal carries checker
-- credentials. It is bound to one resource server, and an mTLS identity is
-- registered at most once, disabled rows included, so it cannot be usable
-- for another audience (IR-090; including disabled rows is inferred). Its
-- allowed_tenant_ids are the rows of resource_server_checker_tenant.
CREATE TABLE resource_server_checker (
    id                    text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT resource_server_checker_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    resource_server_id    text COLLATE "C" NOT NULL
        CONSTRAINT resource_server_checker_resource_server_id_octet_length_check
        CHECK (octet_length(resource_server_id) <= 255)
        CONSTRAINT resource_server_checker_resource_server_id_fkey
        REFERENCES resource_server (id),
    -- The public mTLS identity. Its form (for example a key fingerprint or a
    -- subject DN, which has spaces) is not specified, so only its length is
    -- bounded; the service canonicalizes it, so that the unique constraint
    -- compares like with like (inferred). It may be rotated (inferred).
    public_mtls_identity  text COLLATE "C" NOT NULL UNIQUE CHECK (public_mtls_identity <> '')
        CONSTRAINT resource_server_checker_public_mtls_identity_octet_length_check
        CHECK (octet_length(public_mtls_identity) <= 2048),
    status                text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision              bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    -- Target of the composite reference from resource_server_checker_tenant.
    UNIQUE (id, resource_server_id)
);

-- ResourceServerChecker.allowed_tenant_ids, one row per tenant (lead
-- decision, 2026-11-20): the model and API field is derived from these rows.
-- The checker's tenant set must be a subset of its resource server's
-- assignments (OQ-ADR018-1). The composite references hold the existence
-- half: a row names a checker and an assignment of the same resource server,
-- so a checker can only list a tenant assigned to its own resource server.
-- Leaving out a tenant whose assignment is disabled stays with the service,
-- without editing these rows. A row is added or deleted, never changed; the
-- set is part of the checker, so the service advances the checker's revision
-- with it (inferred: no status or revision of its own). The primary key
-- makes checker_id and tenant_id NOT NULL. The resource_server_id check name
-- is abbreviated to fit the 63-byte identifier limit.
CREATE TABLE resource_server_checker_tenant (
    checker_id          text COLLATE "C"
        CONSTRAINT resource_server_checker_tenant_checker_id_octet_length_check
        CHECK (octet_length(checker_id) <= 255),
    resource_server_id  text COLLATE "C" NOT NULL
        CONSTRAINT resource_server_checker_tenant_server_id_octet_length_check
        CHECK (octet_length(resource_server_id) <= 255),
    tenant_id           text COLLATE "C"
        CONSTRAINT resource_server_checker_tenant_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255),
    PRIMARY KEY (checker_id, tenant_id),
    CONSTRAINT resource_server_checker_tenant_checker_fkey
        FOREIGN KEY (checker_id, resource_server_id)
        REFERENCES resource_server_checker (id, resource_server_id),
    CONSTRAINT resource_server_checker_tenant_assignment_fkey
        FOREIGN KEY (tenant_id, resource_server_id)
        REFERENCES audience_tenant_assignment (tenant_id, resource_server_id)
);

-- ResourceAction, M1a fields (IR-100, IR-104; T14.4). The M1b stream fields
-- (stream_capable, max_stream_duration_seconds, stream_class,
-- max_session_lease_seconds) come with M1b (T14.4; identity-registry
-- section 7.4).
CREATE TABLE resource_action (
    id                            text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT resource_action_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    resource_server_id            text COLLATE "C" NOT NULL
        CONSTRAINT resource_action_resource_server_id_octet_length_check
        CHECK (octet_length(resource_server_id) <= 255)
        CONSTRAINT resource_action_resource_server_id_fkey REFERENCES resource_server (id),
    -- The canonical action coordinate the checker sends; no syntax is
    -- specified, so it is a bounded name as above (inferred).
    action_name                   text COLLATE "C" NOT NULL CHECK (action_name <> '')
        CONSTRAINT resource_action_action_name_no_space_check
        CHECK (action_name !~ '[[:space:][:cntrl:]]')
        CONSTRAINT resource_action_action_name_octet_length_check
        CHECK (octet_length(action_name) <= 2048),
    required_scopes               skyoauth_scope_list   NOT NULL,
    accepted_profiles             skyoauth_profile_list NOT NULL,
    -- Dimension names of the resource server's constraint schema (inferred:
    -- non-empty strings).
    required_resource_dimensions  skyoauth_string_list  NOT NULL,
    -- No default: the service always states it (inferred).
    live_check_required           boolean     NOT NULL,
    status                        text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision                      bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    -- One rule per action coordinate of a resource server (inferred: the
    -- service looks up "the" persisted action, API-072).
    UNIQUE (resource_server_id, action_name)
);

-- IDs are immutable selectors (tasks section 3 "IDs/names"). The audience,
-- the resource server each row belongs to, an assignment's tenant and an
-- action's name are immutable too (inferred: they select what the row
-- governs), as is every column of a checker tenant row (lead decision,
-- 2026-11-20).
CREATE TRIGGER resource_server_immutable
    BEFORE UPDATE ON resource_server
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('id', 'audience');
ALTER TABLE resource_server ENABLE ALWAYS TRIGGER resource_server_immutable;

CREATE TRIGGER audience_tenant_assignment_immutable
    BEFORE UPDATE ON audience_tenant_assignment
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'resource_server_id', 'tenant_id');
ALTER TABLE audience_tenant_assignment ENABLE ALWAYS TRIGGER audience_tenant_assignment_immutable;

CREATE TRIGGER resource_server_checker_immutable
    BEFORE UPDATE ON resource_server_checker
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('id', 'resource_server_id');
ALTER TABLE resource_server_checker ENABLE ALWAYS TRIGGER resource_server_checker_immutable;

CREATE TRIGGER resource_server_checker_tenant_immutable
    BEFORE UPDATE ON resource_server_checker_tenant
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('checker_id', 'resource_server_id', 'tenant_id');
ALTER TABLE resource_server_checker_tenant
    ENABLE ALWAYS TRIGGER resource_server_checker_tenant_immutable;

CREATE TRIGGER resource_action_immutable
    BEFORE UPDATE ON resource_action
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'resource_server_id', 'action_name');
ALTER TABLE resource_action ENABLE ALWAYS TRIGGER resource_action_immutable;

CREATE TRIGGER resource_server_revision
    BEFORE INSERT OR UPDATE ON resource_server
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE resource_server ENABLE ALWAYS TRIGGER resource_server_revision;

CREATE TRIGGER audience_tenant_assignment_revision
    BEFORE INSERT OR UPDATE ON audience_tenant_assignment
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE audience_tenant_assignment ENABLE ALWAYS TRIGGER audience_tenant_assignment_revision;

CREATE TRIGGER resource_server_checker_revision
    BEFORE INSERT OR UPDATE ON resource_server_checker
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE resource_server_checker ENABLE ALWAYS TRIGGER resource_server_checker_revision;

CREATE TRIGGER resource_action_revision
    BEFORE INSERT OR UPDATE ON resource_action
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE resource_action ENABLE ALWAYS TRIGGER resource_action_revision;
