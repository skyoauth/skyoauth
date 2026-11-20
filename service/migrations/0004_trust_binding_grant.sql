-- Trust sources, trust keysets and their versions, principal bindings,
-- service identities and service grants of the M1a domain schema (T10.1),
-- named as in the logical model (docs/skyoauth-tasks.md section 3;
-- identity-registry sections 5.1 and 10; ADR-005, ADR-006, ADR-016,
-- ADR-022). All of them are tenant-owned (design section 7.1), and every
-- reference between them is a composite (tenant_id, ...) foreign key to a
-- (tenant_id, id) unique, so no cross-tenant reference can exist (IR-031;
-- tasks section 3 "Ownership"). The conventions of 0002 and 0003 apply:
-- README.md in this directory has them and the rules left to the service.
-- "(inferred)" marks a choice the specifications do not dictate.
--
-- Every column is NOT NULL unless the logical model marks the field
-- optional or it is a kind-specific trust source field. Every foreign key is
-- named, takes no action on delete or update and is not deferrable. status
-- is 'enabled' or 'disabled' everywhere (inferred, as in 0003: the sources
-- speak of disabling these records, ADR-008 item 3). revision defaults to 1,
-- the only value skyoauth_check_revision() accepts on insert. Delete and
-- truncate guards come with the one follow-up migration for all registry
-- tables (README.md "Follow-ups"); until then only foreign keys hold back a
-- delete.
--
-- Bounds, as in 0003 (lead decision, 2026-11-20): every ID column, own ID or
-- reference, is at most 255 bytes, and every unique free-text key at most
-- 2048 bytes, each with a named <table>_<column>_octet_length_check, so an
-- over-long value fails with 23514 (also when it names a missing row: a
-- CHECK runs before the row enters any index and before the foreign key
-- check), never with the btree error 54000; every composite key stays below
-- the btree limit of about 2700 bytes even when the values do not compress.
-- Where the full name would exceed the 63-byte identifier limit,
-- resource_server_id is abbreviated to server_id, as in 0003. Names and the
-- exact strings below also reject whitespace and control characters
-- (<table>_<column>_no_space_check; [:space:] is ASCII whitespace under
-- "C", [:cntrl:] is U+0000-U+001F and U+007F-U+009F in every collation).
-- Other syntax and Unicode normalization stay with the service. The other
-- checks of a single column keep the names PostgreSQL generates; the rules
-- that tie several columns together are named.

-- A principal row's kind is immutable (0002), so a composite reference to
-- (tenant_id, id, kind) with a constant kind column pins the kind of the
-- referenced principal: a binding and a grant actor name a workload
-- (identity-registry section 5.1; design section 5.6), a service identity a
-- service principal (tasks section 3 "Ownership"). The constant column and
-- its default are the mechanism (inferred). 0002 is frozen, so 0004 bounds
-- the key columns of principal forward-only, as 0003 bounds tenant
-- (inferred, as a consequence of the new key), validated against existing
-- rows.
ALTER TABLE principal ADD CONSTRAINT principal_id_octet_length_check
    CHECK (octet_length(id) <= 255);
ALTER TABLE principal ADD CONSTRAINT principal_tenant_id_octet_length_check
    CHECK (octet_length(tenant_id) <= 255);
ALTER TABLE principal ADD CONSTRAINT principal_tenant_id_id_kind_key UNIQUE (tenant_id, id, kind);

-- name is a tenant-local label, unique within its table and tenant (IR-021;
-- tasks section 3 "IDs/names"), disabled rows included (inferred). As a
-- unique free-text key it is bounded, and as a name it has no whitespace
-- or control character (inferred: the 0003 rule for names, lead decision
-- 2026-11-20, applied to these tenant-unique names); it keeps the database
-- collation, as names do in 0002 and 0003.

-- TrustKeyset: the stable tenant-owned parent of uploaded key versions
-- (ADR-005 item 5; T11.9). It holds no pointer to a current version, so
-- overlapping versions create no circular reference (T11.9).
CREATE TABLE trust_keyset (
    id         text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT trust_keyset_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id  text COLLATE "C" NOT NULL
        CONSTRAINT trust_keyset_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT trust_keyset_tenant_id_fkey REFERENCES tenant (id),
    name       text        NOT NULL CHECK (name <> '')
        CONSTRAINT trust_keyset_name_no_space_check
        CHECK (name !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_keyset_name_octet_length_check
        CHECK (octet_length(name) <= 2048),
    status     text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision   bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

-- TrustKeysetVersion: public-only keys with explicit validity (ADR-005 item
-- 5; T11.3). Versions are immutable (tasks section 3 "Ownership": "their
-- immutable versions"); the model gives them no revision, and that status
-- alone may change is (inferred). Several versions may be active at once.
CREATE TABLE trust_keyset_version (
    id            text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT trust_keyset_version_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id     text COLLATE "C" NOT NULL
        CONSTRAINT trust_keyset_version_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT trust_keyset_version_tenant_id_fkey REFERENCES tenant (id),
    keyset_id     text COLLATE "C" NOT NULL
        CONSTRAINT trust_keyset_version_keyset_id_octet_length_check
        CHECK (octet_length(keyset_id) <= 255),
    -- A JWK Set (RFC 7517 section 5): an object whose "keys" member is a
    -- nonempty array of objects (nonempty is inferred). No key may carry a
    -- private or symmetric key member (RFC 7518 section 6: d, p, q, dp, dq,
    -- qi, oth, k; RFC 8037: d), so a private-key upload is rejected here too
    -- (ADR-005 items 2 and 8; T11.3). Algorithms, sizes and kid uniqueness
    -- are the service's checks.
    public_jwks   jsonb       NOT NULL
        CHECK (jsonb_path_exists(public_jwks,
            'strict $ ? (@.keys.type() == "array" && @.keys.size() > 0)', '{}', true)
            AND NOT jsonb_path_exists(public_jwks,
                'strict $.keys[*] ? (@.type() != "object")', '{}', true)
            AND NOT jsonb_path_exists(public_jwks,
                'lax $.keys[*] ? (exists(@.d) || exists(@.p) || exists(@.q)
                    || exists(@.dp) || exists(@.dq) || exists(@.qi)
                    || exists(@.oth) || exists(@.k))')),
    -- Computed by the service; its algorithm and input are application-layer
    -- (inferred: not unique, compared exactly).
    fingerprint   text COLLATE "C" NOT NULL CHECK (fingerprint <> '')
        CONSTRAINT trust_keyset_version_fingerprint_no_space_check
        CHECK (fingerprint !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_keyset_version_fingerprint_octet_length_check
        CHECK (octet_length(fingerprint) <= 2048),
    effective_at  timestamptz NOT NULL,
    expires_at    timestamptz,
    status        text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    -- Who supplied the keys and from where; no shape is specified (inferred:
    -- a JSON object).
    provenance    jsonb       NOT NULL CHECK (jsonb_typeof(provenance) = 'object'),
    UNIQUE (tenant_id, id),
    CONSTRAINT trust_keyset_version_keyset_id_fkey
        FOREIGN KEY (tenant_id, keyset_id) REFERENCES trust_keyset (tenant_id, id),
    -- A validity window is not empty (inferred).
    CONSTRAINT trust_keyset_version_validity_check CHECK (expires_at > effective_at)
);

-- TrustSource (ADR-005; identity-registry IR-032, IR-151; tasks section 3
-- "Source kinds").
CREATE TABLE trust_source (
    id                             text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT trust_source_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id                      text COLLATE "C" NOT NULL
        CONSTRAINT trust_source_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT trust_source_tenant_id_fkey REFERENCES tenant (id),
    name                           text        NOT NULL CHECK (name <> '')
        CONSTRAINT trust_source_name_no_space_check
        CHECK (name !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_name_octet_length_check
        CHECK (octet_length(name) <= 2048),
    kind                           text COLLATE "C" NOT NULL
        CHECK (kind IN ('oidc_discovery', 'uploaded_jwks', 'kubernetes_token_review')),
    -- Compared exactly and not unique: tenants and clusters may share an
    -- issuer (IR-032). The exact strings of a source (issuer, URLs, secret
    -- references, CA fingerprint) are non-empty, have no whitespace or
    -- control character and are at most 2048 bytes, as exact_destination in
    -- 0002 (inferred: they are compared or resolved exactly).
    exact_issuer                   text COLLATE "C" NOT NULL CHECK (exact_issuer <> '')
        CONSTRAINT trust_source_exact_issuer_no_space_check
        CHECK (exact_issuer !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_exact_issuer_octet_length_check
        CHECK (octet_length(exact_issuer) <= 2048),
    -- discovery_url and token_review_endpoint are matched by value against
    -- an enabled egress_allowlist_entry when they are written (IR-152). They
    -- are not foreign keys: a write that leaves them unchanged must not be
    -- rejected for a missing or disabled entry (IR-152).
    discovery_url                  text COLLATE "C" CHECK (discovery_url <> '')
        CONSTRAINT trust_source_discovery_url_no_space_check
        CHECK (discovery_url !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_discovery_url_octet_length_check
        CHECK (octet_length(discovery_url) <= 2048),
    jwks_keyset_id                 text COLLATE "C"
        CONSTRAINT trust_source_jwks_keyset_id_octet_length_check
        CHECK (octet_length(jwks_keyset_id) <= 255),
    -- Opaque, server-generated and owned by its source (OQ-ADR011-1), so an
    -- ID, unique across sources (inferred).
    cluster_id                     text COLLATE "C" UNIQUE CHECK (cluster_id <> '')
        CONSTRAINT trust_source_cluster_id_octet_length_check
        CHECK (octet_length(cluster_id) <= 255),
    token_review_endpoint          text COLLATE "C" CHECK (token_review_endpoint <> '')
        CONSTRAINT trust_source_token_review_endpoint_no_space_check
        CHECK (token_review_endpoint !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_token_review_endpoint_octet_length_check
        CHECK (octet_length(token_review_endpoint) <= 2048),
    -- Secret references resolve within the tenant's secret_namespace
    -- (IR-034); their syntax is not specified.
    ca_bundle_ref                  text COLLATE "C" CHECK (ca_bundle_ref <> '')
        CONSTRAINT trust_source_ca_bundle_ref_no_space_check
        CHECK (ca_bundle_ref !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_ca_bundle_ref_octet_length_check
        CHECK (octet_length(ca_bundle_ref) <= 2048),
    ca_fingerprint                 text COLLATE "C" CHECK (ca_fingerprint <> '')
        CONSTRAINT trust_source_ca_fingerprint_no_space_check
        CHECK (ca_fingerprint !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_ca_fingerprint_octet_length_check
        CHECK (octet_length(ca_fingerprint) <= 2048),
    reviewer_credential_ref        text COLLATE "C" CHECK (reviewer_credential_ref <> '')
        CONSTRAINT trust_source_reviewer_credential_ref_no_space_check
        CHECK (reviewer_credential_ref !~ '[[:space:][:cntrl:]]')
        CONSTRAINT trust_source_reviewer_credential_ref_octet_length_check
        CHECK (octet_length(reviewer_credential_ref) <= 2048),
    -- No default or bound is given (lifetimes section 8; inferred:
    -- positive).
    review_timeout_ms              integer     CHECK (review_timeout_ms > 0),
    -- Exact proof audiences (IR-014; identity-registry section 10); an
    -- allowlist names at least one (inferred).
    audiences                      skyoauth_string_list NOT NULL
        CHECK (jsonb_array_length(audiences) > 0),
    -- The algorithm allowlist (design section 5.4); the value set is open
    -- (OQ-TP-3), so only non-empty names are checked, and at least one
    -- (inferred).
    algorithms                     skyoauth_string_list
        CHECK (jsonb_array_length(algorithms) > 0),
    -- Evidence bounds (T11.1); no shape is specified (inferred: a JSON
    -- object).
    proof_bounds                   jsonb       NOT NULL CHECK (jsonb_typeof(proof_bounds) = 'object'),
    -- OQ-ADR005-2.
    assertion_profile              text COLLATE "C" NOT NULL
        CHECK (assertion_profile IN ('on_demand_jwt', 'reusable_jwt', 'projected_service_account')),
    -- Set means true: false acknowledges nothing (inferred).
    stale_revocation_acknowledged  boolean     CHECK (stale_revocation_acknowledged),
    replay_mode                    text COLLATE "C" NOT NULL
        CHECK (replay_mode IN ('reusable', 'single_use')),
    status                         text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision                       bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    CONSTRAINT trust_source_jwks_keyset_id_fkey
        FOREIGN KEY (tenant_id, jwks_keyset_id) REFERENCES trust_keyset (tenant_id, id),
    -- Kind-specific fields (ADR-005 item 1; design section 5.4); a field of
    -- another kind is rejected (T11.10 "conflicting kind fields"). Reading
    -- the CA fields as kubernetes_token_review only, and every listed field
    -- of a kind as required for it, is (inferred).
    CONSTRAINT trust_source_discovery_url_kind_check
        CHECK ((discovery_url IS NOT NULL) = (kind = 'oidc_discovery')),
    CONSTRAINT trust_source_jwks_keyset_id_kind_check
        CHECK ((jwks_keyset_id IS NOT NULL) = (kind = 'uploaded_jwks')),
    CONSTRAINT trust_source_token_review_fields_kind_check
        CHECK (CASE WHEN kind = 'kubernetes_token_review'
            THEN num_nulls(cluster_id, token_review_endpoint, ca_bundle_ref, ca_fingerprint,
                           reviewer_credential_ref, review_timeout_ms) = 0
            ELSE num_nonnulls(cluster_id, token_review_endpoint, ca_bundle_ref, ca_fingerprint,
                              reviewer_credential_ref, review_timeout_ms) = 0
            END),
    -- TokenReview verifies no signature locally, so it has no algorithm
    -- allowlist; the other kinds must have one (inferred).
    CONSTRAINT trust_source_algorithms_kind_check
        CHECK ((algorithms IS NOT NULL) = (kind <> 'kubernetes_token_review')),
    -- TokenReview reviews projected service-account tokens (design section
    -- 5.4; that no other assertion profile is allowed is inferred).
    CONSTRAINT trust_source_token_review_profile_check
        CHECK (kind <> 'kubernetes_token_review' OR assertion_profile = 'projected_service_account'),
    -- Required for projected_service_account on uploaded_jwks or
    -- oidc_discovery, rejected on every other source (IR-151).
    CONSTRAINT trust_source_stale_revocation_kind_check
        CHECK ((stale_revocation_acknowledged IS NOT NULL)
            = (kind IN ('oidc_discovery', 'uploaded_jwks')
                AND assertion_profile = 'projected_service_account')),
    -- single_use only with on_demand_jwt on oidc_discovery or uploaded_jwks
    -- (OQ-ADR005-2; ADR-016 items 6 and 8).
    CONSTRAINT trust_source_single_use_replay_check
        CHECK (replay_mode = 'reusable'
            OR (assertion_profile = 'on_demand_jwt' AND kind IN ('oidc_discovery', 'uploaded_jwks')))
);

-- PrincipalBinding (design section 5.3; ADR-016 items 1 to 4; ADR-022): it
-- maps verified evidence of one source to one workload principal.
CREATE TABLE principal_binding (
    id                       text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT principal_binding_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id                text COLLATE "C" NOT NULL
        CONSTRAINT principal_binding_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT principal_binding_tenant_id_fkey REFERENCES tenant (id),
    name                     text        NOT NULL CHECK (name <> '')
        CONSTRAINT principal_binding_name_no_space_check
        CHECK (name !~ '[[:space:][:cntrl:]]')
        CONSTRAINT principal_binding_name_octet_length_check
        CHECK (octet_length(name) <= 2048),
    trust_source_id          text COLLATE "C" NOT NULL
        CONSTRAINT principal_binding_trust_source_id_octet_length_check
        CHECK (octet_length(trust_source_id) <= 255),
    -- The template that fixes the required predicates (ADR-016 item 4). The
    -- source lists these three "for example"; that they are the whole set
    -- is (inferred).
    profile                  text COLLATE "C" NOT NULL
        CHECK (profile IN ('github_production', 'kubernetes_production', 'generic_production')),
    -- ANDed exact-string predicates, claim name to value (identity-registry
    -- section 10; design section 5.3). Every template requires at least one
    -- predicate (ADR-016 item 4), so the object is not empty; that values
    -- are strings only is (inferred).
    claim_match_policy       jsonb       NOT NULL
        CHECK (jsonb_typeof(claim_match_policy) = 'object' AND claim_match_policy <> '{}'
            AND NOT jsonb_path_exists(claim_match_policy,
                'strict $.* ? (@.type() != "string")', '{}', true)),
    workload_principal_id    text COLLATE "C" NOT NULL
        CONSTRAINT principal_binding_workload_principal_id_octet_length_check
        CHECK (octet_length(workload_principal_id) <= 255),
    status                   text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision                 bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    workload_principal_kind  text COLLATE "C" NOT NULL DEFAULT 'workload'
        CONSTRAINT principal_binding_workload_principal_kind_check
        CHECK (workload_principal_kind = 'workload'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    -- Target of the composite reference from service_grant_binding, which
    -- pairs a grant's actor with the binding's principal.
    UNIQUE (tenant_id, id, workload_principal_id),
    CONSTRAINT principal_binding_trust_source_id_fkey
        FOREIGN KEY (tenant_id, trust_source_id) REFERENCES trust_source (tenant_id, id),
    CONSTRAINT principal_binding_workload_principal_id_fkey
        FOREIGN KEY (tenant_id, workload_principal_id, workload_principal_kind)
        REFERENCES principal (tenant_id, id, kind)
);

-- ServiceIdentity: its id is the id of a service principal (tasks section 3
-- "Ownership"), created with it in one transaction (identity-registry
-- section 5.1). It is a possible token subject and carries no checker
-- credentials (IR-044). Its resource_server_ids are the rows of
-- service_identity_resource_server.
CREATE TABLE service_identity (
    id                        text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT service_identity_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id                 text COLLATE "C" NOT NULL
        CONSTRAINT service_identity_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT service_identity_tenant_id_fkey REFERENCES tenant (id),
    name                      text        NOT NULL CHECK (name <> '')
        CONSTRAINT service_identity_name_no_space_check
        CHECK (name !~ '[[:space:][:cntrl:]]')
        CONSTRAINT service_identity_name_octet_length_check
        CHECK (octet_length(name) <= 2048),
    max_scopes                skyoauth_scope_list NOT NULL,
    -- A constraint ceiling (IR-123); its schema is per resource server
    -- (IR-141), so only the object shape is checked (inferred).
    max_resource_constraints  jsonb       NOT NULL
        CHECK (jsonb_typeof(max_resource_constraints) = 'object'),
    status                    text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    revision                  bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    principal_kind            text COLLATE "C" NOT NULL DEFAULT 'service'
        CONSTRAINT service_identity_principal_kind_check
        CHECK (principal_kind = 'service'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    CONSTRAINT service_identity_id_fkey
        FOREIGN KEY (tenant_id, id, principal_kind) REFERENCES principal (tenant_id, id, kind)
);

-- ServiceIdentity.resource_server_ids, one row per audience, as checker
-- tenants in 0003: each names an audience assigned to the service's own
-- tenant (IR-080, IR-083). A row is added or deleted, never changed, and
-- the service advances the identity's revision with it (inferred: no status
-- or revision of its own). The primary key makes service_id and
-- resource_server_id NOT NULL.
CREATE TABLE service_identity_resource_server (
    service_id          text COLLATE "C"
        CONSTRAINT service_identity_resource_server_service_id_octet_length_check
        CHECK (octet_length(service_id) <= 255),
    tenant_id           text COLLATE "C" NOT NULL
        CONSTRAINT service_identity_resource_server_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255),
    resource_server_id  text COLLATE "C"
        CONSTRAINT service_identity_resource_server_server_id_octet_length_check
        CHECK (octet_length(resource_server_id) <= 255),
    PRIMARY KEY (service_id, resource_server_id),
    CONSTRAINT service_identity_resource_server_service_id_fkey
        FOREIGN KEY (tenant_id, service_id) REFERENCES service_identity (tenant_id, id),
    CONSTRAINT service_identity_resource_server_assignment_fkey
        FOREIGN KEY (tenant_id, resource_server_id)
        REFERENCES audience_tenant_assignment (tenant_id, resource_server_id)
);

-- ServiceGrant (design sections 5.6 and 5.7; ADR-006; ADR-022 items 10 to
-- 13). Its allowed_binding_ids are the rows of service_grant_binding and its
-- resource_server_ids those of service_grant_resource_server.
CREATE TABLE service_grant (
    id                    text COLLATE "C" PRIMARY KEY CHECK (id <> '')
        CONSTRAINT service_grant_id_octet_length_check
        CHECK (octet_length(id) <= 255),
    tenant_id             text COLLATE "C" NOT NULL
        CONSTRAINT service_grant_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255)
        CONSTRAINT service_grant_tenant_id_fkey REFERENCES tenant (id),
    name                  text        NOT NULL CHECK (name <> '')
        CONSTRAINT service_grant_name_no_space_check
        CHECK (name !~ '[[:space:][:cntrl:]]')
        CONSTRAINT service_grant_name_octet_length_check
        CHECK (octet_length(name) <= 2048),
    -- The workload actor (design section 5.6).
    actor_principal_id    text COLLATE "C" NOT NULL
        CONSTRAINT service_grant_actor_principal_id_octet_length_check
        CHECK (octet_length(actor_principal_id) <= 255),
    target_service_id     text COLLATE "C"
        CONSTRAINT service_grant_target_service_id_octet_length_check
        CHECK (octet_length(target_service_id) <= 255),
    -- OQ-ADR006-1.
    mode                  text COLLATE "C" NOT NULL
        CHECK (mode IN ('direct', 'delegation', 'impersonation')),
    scopes                skyoauth_scope_list NOT NULL,
    default_scopes        skyoauth_scope_list,
    -- The grant's constraint ceiling (IR-123), checked as
    -- max_resource_constraints (inferred).
    resource_constraints  jsonb       NOT NULL CHECK (jsonb_typeof(resource_constraints) = 'object'),
    -- Seconds (inferred from the export name max_lifetime_seconds, OQ-IR-6).
    -- A grant may only shorten the 300 s wif maximum (token-profiles
    -- section 7).
    max_ttl               integer     NOT NULL CHECK (max_ttl BETWEEN 1 AND 300),
    valid_until           timestamptz,
    status                text COLLATE "C" NOT NULL CHECK (status IN ('enabled', 'disabled')),
    -- OQ-ADR006-1.
    activation_state      text COLLATE "C" NOT NULL
        CHECK (activation_state IN ('not_required', 'requires_reapproval')),
    revision              bigint      NOT NULL DEFAULT 1 CHECK (revision >= 1),
    actor_principal_kind  text COLLATE "C" NOT NULL DEFAULT 'workload'
        CONSTRAINT service_grant_actor_principal_kind_check
        CHECK (actor_principal_kind = 'workload'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    -- Target of the composite reference from service_grant_binding.
    UNIQUE (tenant_id, id, actor_principal_id),
    CONSTRAINT service_grant_actor_principal_id_fkey
        FOREIGN KEY (tenant_id, actor_principal_id, actor_principal_kind)
        REFERENCES principal (tenant_id, id, kind),
    CONSTRAINT service_grant_target_service_id_fkey
        FOREIGN KEY (tenant_id, target_service_id) REFERENCES service_identity (tenant_id, id),
    -- A direct grant has no target; delegation and impersonation name a
    -- same-tenant service (IR-045; OQ-ADR006-1).
    CONSTRAINT service_grant_target_mode_check
        CHECK ((target_service_id IS NULL) = (mode = 'direct')),
    -- Impersonation is stored only disabled and requiring reapproval
    -- (design section 5.6; T10.11). That direct and delegation grants carry
    -- not_required is (inferred).
    CONSTRAINT service_grant_activation_mode_check
        CHECK ((activation_state = 'requires_reapproval') = (mode = 'impersonation')),
    CONSTRAINT service_grant_impersonation_disabled_check
        CHECK (mode <> 'impersonation' OR status = 'disabled'),
    -- Explicit and nonempty when present, and within the grant's own scopes
    -- (IR-063); the other ceilings can change later, so the service checks
    -- them.
    CONSTRAINT service_grant_default_scopes_check
        CHECK (default_scopes IS NULL
            OR (jsonb_array_length(default_scopes) > 0 AND scopes @> default_scopes))
);

-- ServiceGrant.allowed_binding_ids, one row per binding. Both composite
-- references carry the grant's actor, so a row can only name a same-tenant
-- binding of that actor: cross-actor and cross-tenant references are
-- rejected (ADR-022 item 13; T12.7). The set is nonempty (identity-registry
-- section 10), checked at commit below. A row is added or deleted, never
-- changed, and the service advances the grant's revision with it (inferred:
-- no status or revision of its own). The primary key makes grant_id and
-- binding_id NOT NULL.
CREATE TABLE service_grant_binding (
    grant_id            text COLLATE "C"
        CONSTRAINT service_grant_binding_grant_id_octet_length_check
        CHECK (octet_length(grant_id) <= 255),
    binding_id          text COLLATE "C"
        CONSTRAINT service_grant_binding_binding_id_octet_length_check
        CHECK (octet_length(binding_id) <= 255),
    tenant_id           text COLLATE "C" NOT NULL
        CONSTRAINT service_grant_binding_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255),
    actor_principal_id  text COLLATE "C" NOT NULL
        CONSTRAINT service_grant_binding_actor_principal_id_octet_length_check
        CHECK (octet_length(actor_principal_id) <= 255),
    PRIMARY KEY (grant_id, binding_id),
    CONSTRAINT service_grant_binding_grant_id_fkey
        FOREIGN KEY (tenant_id, grant_id, actor_principal_id)
        REFERENCES service_grant (tenant_id, id, actor_principal_id),
    CONSTRAINT service_grant_binding_binding_id_fkey
        FOREIGN KEY (tenant_id, binding_id, actor_principal_id)
        REFERENCES principal_binding (tenant_id, id, workload_principal_id)
);

-- ServiceGrant.resource_server_ids, one row per audience, as for service
-- identities (IR-080, IR-083). The primary key makes grant_id and
-- resource_server_id NOT NULL.
CREATE TABLE service_grant_resource_server (
    grant_id            text COLLATE "C"
        CONSTRAINT service_grant_resource_server_grant_id_octet_length_check
        CHECK (octet_length(grant_id) <= 255),
    tenant_id           text COLLATE "C" NOT NULL
        CONSTRAINT service_grant_resource_server_tenant_id_octet_length_check
        CHECK (octet_length(tenant_id) <= 255),
    resource_server_id  text COLLATE "C"
        CONSTRAINT service_grant_resource_server_server_id_octet_length_check
        CHECK (octet_length(resource_server_id) <= 255),
    PRIMARY KEY (grant_id, resource_server_id),
    CONSTRAINT service_grant_resource_server_grant_id_fkey
        FOREIGN KEY (tenant_id, grant_id) REFERENCES service_grant (tenant_id, id),
    CONSTRAINT service_grant_resource_server_assignment_fkey
        FOREIGN KEY (tenant_id, resource_server_id)
        REFERENCES audience_tenant_assignment (tenant_id, resource_server_id)
);

-- Immutable columns. IDs are immutable selectors (tasks section 3
-- "IDs/names"); keyset versions are immutable (tasks section 3
-- "Ownership"). Inferred: the owning tenant everywhere (as for principal in
-- 0002); every keyset version column but status; a source's kind,
-- cluster_id ("stable cluster ID", design section 5.4) and jwks_keyset_id
-- ("stable" parent, ADR-005 item 5); a binding's source and principal; a
-- grant's actor, target and mode (the selected grant determines the actor
-- and target, ADR-022 item 10, and an impersonation grant is never treated
-- as delegation, design section 5.6); and every column of a list row (as
-- for checker tenant rows in 0003).
CREATE TRIGGER trust_keyset_immutable
    BEFORE UPDATE ON trust_keyset
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('id', 'tenant_id');
ALTER TABLE trust_keyset ENABLE ALWAYS TRIGGER trust_keyset_immutable;

CREATE TRIGGER trust_keyset_version_immutable
    BEFORE UPDATE ON trust_keyset_version
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'tenant_id', 'keyset_id', 'public_jwks',
            'fingerprint', 'effective_at', 'expires_at', 'provenance');
ALTER TABLE trust_keyset_version ENABLE ALWAYS TRIGGER trust_keyset_version_immutable;

CREATE TRIGGER trust_source_immutable
    BEFORE UPDATE ON trust_source
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'tenant_id', 'kind', 'cluster_id', 'jwks_keyset_id');
ALTER TABLE trust_source ENABLE ALWAYS TRIGGER trust_source_immutable;

CREATE TRIGGER principal_binding_immutable
    BEFORE UPDATE ON principal_binding
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'tenant_id', 'trust_source_id', 'workload_principal_id');
ALTER TABLE principal_binding ENABLE ALWAYS TRIGGER principal_binding_immutable;

CREATE TRIGGER service_identity_immutable
    BEFORE UPDATE ON service_identity
    FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('id', 'tenant_id');
ALTER TABLE service_identity ENABLE ALWAYS TRIGGER service_identity_immutable;

CREATE TRIGGER service_identity_resource_server_immutable
    BEFORE UPDATE ON service_identity_resource_server
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('service_id', 'tenant_id', 'resource_server_id');
ALTER TABLE service_identity_resource_server
    ENABLE ALWAYS TRIGGER service_identity_resource_server_immutable;

CREATE TRIGGER service_grant_immutable
    BEFORE UPDATE ON service_grant
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('id', 'tenant_id', 'actor_principal_id',
            'target_service_id', 'mode');
ALTER TABLE service_grant ENABLE ALWAYS TRIGGER service_grant_immutable;

CREATE TRIGGER service_grant_binding_immutable
    BEFORE UPDATE ON service_grant_binding
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('grant_id', 'binding_id', 'tenant_id',
            'actor_principal_id');
ALTER TABLE service_grant_binding ENABLE ALWAYS TRIGGER service_grant_binding_immutable;

CREATE TRIGGER service_grant_resource_server_immutable
    BEFORE UPDATE ON service_grant_resource_server
    FOR EACH ROW EXECUTE FUNCTION
        skyoauth_reject_immutable_change('grant_id', 'tenant_id', 'resource_server_id');
ALTER TABLE service_grant_resource_server
    ENABLE ALWAYS TRIGGER service_grant_resource_server_immutable;

CREATE TRIGGER trust_keyset_revision
    BEFORE INSERT OR UPDATE ON trust_keyset
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE trust_keyset ENABLE ALWAYS TRIGGER trust_keyset_revision;

CREATE TRIGGER trust_source_revision
    BEFORE INSERT OR UPDATE ON trust_source
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE trust_source ENABLE ALWAYS TRIGGER trust_source_revision;

CREATE TRIGGER principal_binding_revision
    BEFORE INSERT OR UPDATE ON principal_binding
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE principal_binding ENABLE ALWAYS TRIGGER principal_binding_revision;

CREATE TRIGGER service_identity_revision
    BEFORE INSERT OR UPDATE ON service_identity
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE service_identity ENABLE ALWAYS TRIGGER service_identity_revision;

CREATE TRIGGER service_grant_revision
    BEFORE INSERT OR UPDATE ON service_grant
    FOR EACH ROW EXECUTE FUNCTION skyoauth_check_revision();
ALTER TABLE service_grant ENABLE ALWAYS TRIGGER service_grant_revision;

-- allowed_binding_ids is nonempty (identity-registry section 10): by
-- commit, a grant inserted in the transaction has a binding row, and a
-- binding row deleted in the transaction was not the last of a grant that
-- still exists. A hard delete of a grant (ADR-008 item 3) deletes its rows
-- and then the grant. The check locks the grant row (FOR NO KEY UPDATE, so
-- the caller needs UPDATE on service_grant), so concurrent removals under
-- READ COMMITTED wait for each other and then see each other's deletes
-- (inferred). The function reads tables, so it is created as the 0002 chain
-- functions are: schema resolved by current_schema(), pinned search_path,
-- tables named with the schema, body passed as a quoted literal (%L).
DO $migration$
DECLARE
    schema_name constant text := current_schema();
BEGIN
    EXECUTE format('CREATE FUNCTION %I() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, %I, pg_temp
    AS %L', 'skyoauth_service_grant_has_binding', schema_name,
        replace($body$
DECLARE
    grant_tenant text COLLATE "C";
    grant_key text COLLATE "C";
BEGIN
    IF TG_OP = 'INSERT' THEN
        grant_tenant := NEW.tenant_id;
        grant_key := NEW.id;
    ELSE
        grant_tenant := OLD.tenant_id;
        grant_key := OLD.grant_id;
    END IF;
    PERFORM FROM @schema@.service_grant g
        WHERE g.tenant_id = grant_tenant AND g.id = grant_key
        FOR NO KEY UPDATE;
    IF FOUND AND NOT EXISTS (
        SELECT FROM @schema@.service_grant_binding b WHERE b.grant_id = grant_key
    ) THEN
        RAISE EXCEPTION 'service grant % has no allowed binding', grant_key
            USING ERRCODE = 'SK001';
    END IF;
    RETURN NULL;
END;
$body$, '@schema@', quote_ident(schema_name)));
END;
$migration$;

CREATE CONSTRAINT TRIGGER service_grant_has_binding
    AFTER INSERT ON service_grant
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION skyoauth_service_grant_has_binding();
ALTER TABLE service_grant ENABLE ALWAYS TRIGGER service_grant_has_binding;

CREATE CONSTRAINT TRIGGER service_grant_binding_keeps_one
    AFTER DELETE ON service_grant_binding
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION skyoauth_service_grant_has_binding();
ALTER TABLE service_grant_binding ENABLE ALWAYS TRIGGER service_grant_binding_keeps_one;
