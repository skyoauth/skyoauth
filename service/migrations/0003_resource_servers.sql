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
-- Rows are disabled, not deleted (no DELETE endpoint, public-api section 7);
-- whether a delete is ever allowed is open, so only foreign keys hold one
-- back (README.md "Follow-ups").

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

-- IDs and names with no specified syntax: non-empty strings (inferred).
CREATE DOMAIN skyoauth_string_list AS jsonb
    CHECK (jsonb_typeof(VALUE) = 'array' AND NOT jsonb_path_exists(VALUE,
        'strict $[*] ? (@.type() != "string" || @ == "")', '{}', true));

-- ResourceServer (IR-070, IR-071). The audience is globally unique, exact
-- and immutable. Its syntax and comparison rules are open (OQ-IR-9), so the
-- database compares it byte-wise and only rejects an empty value.
CREATE TABLE resource_server (
    id                   text COLLATE "C" PRIMARY KEY CHECK (id <> ''),
    audience             text COLLATE "C" NOT NULL UNIQUE CHECK (audience <> ''),
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
-- a tenant can only reference an audience assigned to it.
CREATE TABLE audience_tenant_assignment (
    id                   text COLLATE "C" PRIMARY KEY CHECK (id <> ''),
    resource_server_id   text COLLATE "C" NOT NULL REFERENCES resource_server (id),
    tenant_id            text COLLATE "C" NOT NULL REFERENCES tenant (id),
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
-- for another audience (IR-090; including disabled rows is inferred).
CREATE TABLE resource_server_checker (
    id                    text COLLATE "C" PRIMARY KEY CHECK (id <> ''),
    resource_server_id    text COLLATE "C" NOT NULL REFERENCES resource_server (id),
    -- The public mTLS identity. Its form (for example a certificate or key
    -- fingerprint) is not specified; the service canonicalizes it, so that
    -- the unique constraint compares like with like (inferred).
    public_mtls_identity  text COLLATE "C" NOT NULL UNIQUE CHECK (public_mtls_identity <> ''),
    -- Tenant IDs. That each is a tenant with an enabled assignment to this
    -- resource server (OQ-ADR018-1) is checked by the service: a jsonb
    -- element cannot carry a foreign key.
    allowed_tenant_ids    skyoauth_string_list NOT NULL,
    status                text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision              bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

-- ResourceAction, M1a fields (IR-100, IR-104; T14.4). The M1b stream fields
-- (stream_capable, max_stream_duration_seconds, stream_class,
-- max_session_lease_seconds) come with M1b (T14.4; identity-registry
-- section 7.4).
CREATE TABLE resource_action (
    id                            text COLLATE "C" PRIMARY KEY CHECK (id <> ''),
    resource_server_id            text COLLATE "C" NOT NULL REFERENCES resource_server (id),
    -- The canonical action coordinate the checker sends; no syntax is
    -- specified (inferred: non-empty).
    action_name                   text COLLATE "C" NOT NULL CHECK (action_name <> ''),
    required_scopes               skyoauth_scope_list   NOT NULL,
    accepted_profiles             skyoauth_profile_list NOT NULL,
    -- Dimension names of the resource server's constraint schema (inferred:
    -- non-empty strings).
    required_resource_dimensions  skyoauth_string_list  NOT NULL,
    live_check_required           boolean     NOT NULL,
    status                        text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision                      bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    UNIQUE (resource_server_id, action_name)
);

-- Immutable selectors (tasks section 3 "IDs/names"): the IDs, the audience,
-- the resource server each row belongs to, an assignment's tenant and an
-- action's name.
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
