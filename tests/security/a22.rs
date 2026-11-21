//! A22: email-only link or upstream admin-role claim. Expected: no
//! automatic linking or operator elevation (tasks §8; T13.1, T13.6, T30.4,
//! T52.3). M1a positive: a registered mTLS `adm` credential with an active
//! role.
//!
//! **A22 partial: the operator registry slice only; A22 M1a stays planned
//! (scope "operator").** These tests are registered on A22's planned M1a
//! stage, so they are no evidence for it: the reporter lists their results
//! as not counted, and they are no claim. They run through the typed
//! registry API (`skyoauth_service::persistence::registry`: the operator
//! rows, [`authorize_operator`] and [`authorize_operator_locked`]) against
//! a real PostgreSQL, one fresh database per test, with no SQL of their own.
//! The fixture is local: tenants `ten_a` and `ten_b`, and operators
//! enrolled through the registry, each with one identity, one credential
//! and one role binding, all enabled. Every test runs in both tenants; the
//! first positive and the scope and other-registries negatives also in the
//! instance scope.
//!
//! - **Positive.** An operator whose registered, unrevoked credential,
//!   enabled identity and enabled binding are created through the registry
//!   is authorized with exactly those three rows' IDs and its role, in
//!   `ten_a`, in `ten_b` and (as `security_admin`) in the instance; the
//!   same key with any other role, in any other scope, or near-miss forms
//!   of the key (another case, a prefix, an extension, a trailing space) is
//!   refused (`a22_pos_registered_credential_with_active_role_authorizes`).
//!   Inside a transaction, the locked lookup returns the hit the plain
//!   lookup returns; after the transaction itself pulls a lever on the rows the
//!   locked lookup holds, both give the same `None` as an unknown key, a
//!   wrong scope, a wrong role and a credential created `disabled`, and the
//!   rollback leaves the hit as it was
//!   (`a22_pos_locked_lookup_equals_the_plain_lookup_and_the_same_none_for_every_lever`).
//! - **Negative.** Each lever, pulled alone on a fresh operator through the
//!   registry's own mutator (`disable_admin_identity`,
//!   `revoke_admin_credential`, `update_admin_role_binding` to `disabled`),
//!   turns its hit into `None`, the same `None` as a never-registered key's,
//!   and leaves the other operators' hits standing; an operator whose
//!   credential is created `disabled` (never revoked), with its identity and
//!   binding enabled, is not a lever but gives that same `None` from the
//!   start (`a22_neg_each_lever_flips_a_hit_to_the_same_none`). With one
//!   operator per role and scope the schema allows, each key is authorized
//!   for its own role and scope only: a tenant binding never authorizes another
//!   tenant or the instance, an instance binding never a tenant,
//!   `security_admin` never stands in for a tenant role, and no role stands
//!   in for another (`a22_neg_scope_and_role_never_inherit`). The IDs and
//!   names of other registries' rows, used as the key, never authorize
//!   (`a22_neg_other_registries_identities_never_authorize`; see its docs).
//!   A store that cannot be reached is an `Err`, never a hit or a miss
//!   (`a22_neg_store_unavailable_is_an_error_not_a_grant`).
//!
//! No test here re-enables a binding, or asserts anything about doing so:
//! whether a re-enable needs an approval belongs to the service layer
//! (`update_admin_role_binding`).
//!
//! **Missing, so not a claim.** A22 M1a needs the operator's path end to
//! end, and none of these is built:
//!
//! - The mTLS handshake and the deployment trust anchor
//!   (`trust_anchor_ref`): the lookup takes `public_identity` as the caller
//!   canonicalized it after a handshake that no test here performs. That is
//!   the operator client's side, T13.10 (`skyoauth-operator`), which does
//!   not exist yet.
//! - The OP harness leg (T13.6): an operator endpoint that receives a forged
//!   upstream admin-role claim and refuses it; a compromised-IdP session;
//!   replayed recovery; concurrent bootstrap; a missing audit sink; and the
//!   rest of T13.6. No operator endpoint exists yet.
//! - The OIDC leg (the row's mock human IdP): an upstream admin-role claim
//!   or a human session presented where operator authority is needed, which
//!   must never confer it.
//!
//! The M3 stage, "linking" (an explicit verified link positive and the
//! email-only link negative; T30.4, T52.3), is not owned here. A22 has no
//! M4 stage.
//!
//! Not covered here, because `service/tests/registry_operator.rs` covers
//! it: the status matrices of every role and scope shape (identities,
//! credentials and bindings created disabled, credentials created and then
//! revoked); the `revoked_at` check on its own, observable only with
//! `admin_credential_revoked_disabled_check` dropped; empty, over-long, NFD
//! and other near-miss keys and tenant IDs; a NUL character; the one-way
//! state in the database and the refusal to register a revoked key again;
//! an operator with several bindings; and the locked lookup's concurrency
//! (a change committed before it, between its read and its lock, or
//! waiting for its commit; its lock order).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AdminCredential, AdminIdentity, AdminRole, AdminRoleBinding, AdminRoleBindingChanges,
        AssertionProfile, AuthorizedOperator, JsonObject, NewAdminCredential, NewAdminIdentity,
        NewAdminRoleBinding, NewPrincipal, NewTenant, NewTrustSource, OperatorRequest,
        OperatorScope, PrincipalKind, RegistryError, ReplayMode, Status, TrustSourceKind,
        authorize_operator, authorize_operator_locked,
    },
};
use sqlx::{PgConnection, PgExecutor};

const TENANTS: [&str; 2] = ["ten_a", "ten_b"];

const ROLES: [AdminRole; 5] = [
    AdminRole::SecurityAdmin,
    AdminRole::TrustAdmin,
    AdminRole::ClientAdmin,
    AdminRole::ProviderAdmin,
    AdminRole::Auditor,
];

/// Every scope a request can name here: the instance and both tenants.
const SCOPES: [OperatorScope<'static>; 3] = [
    OperatorScope::Instance,
    OperatorScope::Tenant(TENANTS[0]),
    OperatorScope::Tenant(TENANTS[1]),
];

/// The role and scope shapes the schema allows
/// (`admin_role_binding_scope_check`), in both tenants: `security_admin`
/// and an `auditor` of the instance, and `trust_admin`, `client_admin`,
/// `provider_admin` and an `auditor` of each tenant.
const SHAPES: [(AdminRole, Option<&str>); 10] = [
    (AdminRole::SecurityAdmin, None),
    (AdminRole::Auditor, None),
    (AdminRole::TrustAdmin, Some(TENANTS[0])),
    (AdminRole::ClientAdmin, Some(TENANTS[0])),
    (AdminRole::ProviderAdmin, Some(TENANTS[0])),
    (AdminRole::Auditor, Some(TENANTS[0])),
    (AdminRole::TrustAdmin, Some(TENANTS[1])),
    (AdminRole::ClientAdmin, Some(TENANTS[1])),
    (AdminRole::ProviderAdmin, Some(TENANTS[1])),
    (AdminRole::Auditor, Some(TENANTS[1])),
];

/// A canonical key that no credential has.
const NEVER_REGISTERED: &str = "key_never_registered";

/// The caller's `now` for every write that takes one; the registry never
/// reads the database's clock.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

fn scope_of(tenant: Option<&str>) -> OperatorScope<'_> {
    match tenant {
        None => OperatorScope::Instance,
        Some(tenant) => OperatorScope::Tenant(tenant),
    }
}

/// A short name of a role and scope, for operator IDs and messages.
fn shape_name(role: AdminRole, tenant: Option<&str>) -> String {
    format!("{role}_{}", tenant.unwrap_or("instance"))
}

/// The rows of one operator enrolled through the registry, as it returned
/// them.
#[derive(Debug, Clone)]
struct Operator {
    identity: AdminIdentity,
    credential: AdminCredential,
    binding: AdminRoleBinding,
}

impl Operator {
    fn scope(&self) -> OperatorScope<'_> {
        scope_of(self.binding.tenant_id.as_deref())
    }

    /// A request with this operator's key, role and scope.
    fn request(&self) -> OperatorRequest<'_> {
        OperatorRequest {
            public_identity: &self.credential.public_identity,
            scope: self.scope(),
            role: self.binding.role,
        }
    }

    /// The hit of [`Operator::request`]: exactly this operator's rows.
    fn hit(&self) -> AuthorizedOperator {
        AuthorizedOperator {
            admin_id: self.identity.id.clone(),
            credential_id: self.credential.id.clone(),
            binding_id: self.binding.id.clone(),
            role: self.binding.role,
        }
    }
}

/// A fresh database with tenants `ten_a` and `ten_b`.
async fn fixture() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for (tenant, namespace) in TENANTS.into_iter().zip(["ns_a", "ns_b"]) {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: tenant.into(),
                name: format!("Tenant {tenant}"),
                secret_namespace: namespace.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    (db, pool)
}

/// Enrolls operator `adm_<name>` through the registry: an enabled
/// identity, an enabled credential `crd_<name>` with key `key_<name>`, and
/// an enabled binding `rb_<name>` of `role` in `tenant` (`None`: the
/// instance). Checks that each row was stored as asked.
async fn enroll(pool: &PgPool, name: &str, role: AdminRole, tenant: Option<&str>) -> Operator {
    enroll_with_credential(pool, name, role, tenant, Status::Enabled).await
}

/// [`enroll`], with the credential created with `credential_status`
/// (unrevoked either way).
async fn enroll_with_credential(
    pool: &PgPool,
    name: &str,
    role: AdminRole,
    tenant: Option<&str>,
    credential_status: Status,
) -> Operator {
    let identity = registry::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: format!("adm_{name}"),
            status: Status::Enabled,
            created_at: now(),
        },
    )
    .await
    .unwrap();
    let credential = registry::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: format!("crd_{name}"),
            admin_id: identity.id.clone(),
            public_identity: format!("key_{name}"),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: credential_status,
        },
    )
    .await
    .unwrap();
    let binding = registry::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: format!("rb_{name}"),
            admin_id: identity.id.clone(),
            role,
            tenant_id: tenant.map(Into::into),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    assert_eq!(identity.status, Status::Enabled);
    assert_eq!(
        (credential.status, credential.revoked_at),
        (credential_status, None)
    );
    assert_eq!(
        (
            binding.role,
            binding.tenant_id.as_deref(),
            binding.status,
            binding.revision
        ),
        (role, tenant, Status::Enabled, 1)
    );
    Operator {
        identity,
        credential,
        binding,
    }
}

/// One operator per shape of [`SHAPES`], named after its shape.
async fn enroll_every_shape(pool: &PgPool) -> Vec<Operator> {
    let mut operators = Vec::new();
    for (role, tenant) in SHAPES {
        operators.push(enroll(pool, &shape_name(role, tenant), role, tenant).await);
    }
    operators
}

fn request<'a>(key: &'a str, role: AdminRole, scope: OperatorScope<'a>) -> OperatorRequest<'a> {
    OperatorRequest {
        public_identity: key,
        scope,
        role,
    }
}

async fn authorize<'e>(
    executor: impl PgExecutor<'e>,
    request: &OperatorRequest<'_>,
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    authorize_operator(executor, request).await
}

/// `result` is `Ok(None)`, printed exactly as `same` (a never-registered
/// key's result) is: one value and one text for every miss.
#[track_caller]
fn assert_same_none(
    result: &Result<Option<AuthorizedOperator>, RegistryError>,
    same: &Result<Option<AuthorizedOperator>, RegistryError>,
    what: &str,
) {
    assert!(matches!(result, Ok(None)), "{what}: {result:?}");
    assert!(matches!(same, Ok(None)), "{what}: {same:?}");
    assert_eq!(format!("{result:?}"), format!("{same:?}"), "{what}");
}

/// One change to one of the three rows that authorize an operator, each
/// through the registry's own mutator.
#[derive(Debug, Clone, Copy)]
enum Lever {
    DisableIdentity,
    RevokeCredential,
    DisableBinding,
}

const LEVERS: [Lever; 3] = [
    Lever::DisableIdentity,
    Lever::RevokeCredential,
    Lever::DisableBinding,
];

impl Lever {
    fn name(self) -> &'static str {
        match self {
            Lever::DisableIdentity => "off",
            Lever::RevokeCredential => "rev",
            Lever::DisableBinding => "bdis",
        }
    }

    /// Pulls this lever on `operator` and checks that the mutator changed
    /// exactly that: the identity disabled; the credential revoked at
    /// [`now`] and disabled; the binding disabled at revision 2.
    async fn pull(self, conn: &mut PgConnection, operator: &Operator) {
        match self {
            Lever::DisableIdentity => {
                let identity = registry::disable_admin_identity(&mut *conn, &operator.identity.id)
                    .await
                    .unwrap();
                assert_eq!(
                    identity,
                    AdminIdentity {
                        status: Status::Disabled,
                        ..operator.identity.clone()
                    }
                );
            }
            Lever::RevokeCredential => {
                let credential =
                    registry::revoke_admin_credential(&mut *conn, &operator.credential.id, now())
                        .await
                        .unwrap();
                assert_eq!(
                    credential,
                    AdminCredential {
                        status: Status::Disabled,
                        revoked_at: Some(now()),
                        ..operator.credential.clone()
                    }
                );
            }
            Lever::DisableBinding => {
                let binding = registry::update_admin_role_binding(
                    &mut *conn,
                    &operator.binding.id,
                    operator.binding.revision,
                    &AdminRoleBindingChanges {
                        status: Status::Disabled,
                    },
                )
                .await
                .unwrap();
                assert_eq!(
                    binding,
                    AdminRoleBinding {
                        status: Status::Disabled,
                        revision: operator.binding.revision + 1,
                        ..operator.binding.clone()
                    }
                );
            }
        }
    }
}

/// One fresh `trust_admin` per lever and tenant, `adm_<lever>_<tenant>`.
async fn enroll_one_per_lever(pool: &PgPool) -> Vec<(Lever, Operator)> {
    let mut operators = Vec::new();
    for tenant in TENANTS {
        for lever in LEVERS {
            let name = format!("{}_{tenant}", lever.name());
            let operator = enroll(pool, &name, AdminRole::TrustAdmin, Some(tenant)).await;
            operators.push((lever, operator));
        }
    }
    operators
}

/// One `trust_admin` per tenant, `adm_cdis_<tenant>`, whose credential is
/// created `disabled` (and never revoked) while its identity and binding
/// are enabled: not a lever pulled on a hit, an operator that never had
/// one.
async fn enroll_credential_created_disabled(pool: &PgPool) -> Vec<Operator> {
    let mut operators = Vec::new();
    for tenant in TENANTS {
        let name = format!("cdis_{tenant}");
        operators.push(
            enroll_with_credential(
                pool,
                &name,
                AdminRole::TrustAdmin,
                Some(tenant),
                Status::Disabled,
            )
            .await,
        );
    }
    operators
}

#[tokio::test]
async fn a22_pos_registered_credential_with_active_role_authorizes() {
    let (db, pool) = fixture().await;
    let mut operators = Vec::new();
    for tenant in TENANTS {
        operators.push(
            enroll(
                &pool,
                &format!("trust_{tenant}"),
                AdminRole::TrustAdmin,
                Some(tenant),
            )
            .await,
        );
    }
    operators.push(enroll(&pool, "sec", AdminRole::SecurityAdmin, None).await);

    for operator in &operators {
        let found = authorize(&pool, &operator.request()).await.unwrap();
        assert_eq!(found, Some(operator.hit()), "{operator:?}");
        // Exactly the rows enrolled, as the registry reads them back.
        let found = found.unwrap();
        assert_eq!(
            registry::get_admin_identity(&pool, &found.admin_id)
                .await
                .unwrap(),
            operator.identity
        );
        let credential = registry::get_admin_credential(&pool, &found.credential_id)
            .await
            .unwrap();
        assert_eq!(credential, operator.credential);
        assert_eq!(credential.admin_id, found.admin_id);
        let binding = registry::get_admin_role_binding(&pool, &found.binding_id)
            .await
            .unwrap();
        assert_eq!(binding, operator.binding);
        assert_eq!(
            (&binding.admin_id[..], binding.role),
            (&found.admin_id[..], found.role)
        );

        // The same key with any other role, or in any other scope, is
        // refused.
        let key = &operator.credential.public_identity[..];
        for role in ROLES {
            for scope in SCOPES {
                if (role, scope) == (operator.binding.role, operator.scope()) {
                    continue;
                }
                assert_eq!(
                    authorize(&pool, &request(key, role, scope)).await.unwrap(),
                    None,
                    "{key} {role} {scope:?}"
                );
            }
        }
        // Only exactly that key: another case, a prefix, an extension.
        let (role, scope) = (operator.binding.role, operator.scope());
        for near in [
            key.to_uppercase(),
            key[..key.len() - 1].to_owned(),
            format!("{key}x"),
            format!("{key} "),
        ] {
            assert_eq!(
                authorize(&pool, &request(&near, role, scope))
                    .await
                    .unwrap(),
                None,
                "{near:?}"
            );
        }
        // And the hit itself is unchanged by the lookups.
        assert_eq!(
            authorize(&pool, &operator.request()).await.unwrap(),
            Some(operator.hit())
        );
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a22_neg_each_lever_flips_a_hit_to_the_same_none() {
    let (db, pool) = fixture().await;
    let operators = enroll_one_per_lever(&pool).await;
    let created_disabled = enroll_credential_created_disabled(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let mut nones = Vec::new();
    // Not a lever: a credential created disabled, never revoked, of an
    // otherwise enabled operator, is the same `None` from the start.
    for operator in &created_disabled {
        let result = authorize(&pool, &operator.request()).await;
        let never = authorize(
            &pool,
            &request(NEVER_REGISTERED, operator.binding.role, operator.scope()),
        )
        .await;
        assert_same_none(
            &result,
            &never,
            &format!("credential created disabled {operator:?}"),
        );
        nones.push(format!("{result:?}"));
    }
    for (n, (lever, operator)) in operators.iter().enumerate() {
        // Every operator not flipped yet still has its hit; the ones
        // flipped before stay `None`.
        for (m, (_, other)) in operators.iter().enumerate() {
            let found = authorize(&pool, &other.request()).await.unwrap();
            let expected = (m >= n).then(|| other.hit());
            assert_eq!(found, expected, "before {lever:?} of {n}: {m}");
        }
        lever.pull(&mut conn, operator).await;
        let after = authorize(&pool, &operator.request()).await;
        let never = authorize(
            &pool,
            &request(NEVER_REGISTERED, operator.binding.role, operator.scope()),
        )
        .await;
        assert_same_none(&after, &never, &format!("{lever:?} {operator:?}"));
        nones.push(format!("{after:?}"));
    }
    // The credentials created disabled are still `None`.
    for operator in &created_disabled {
        assert_eq!(
            authorize(&pool, &operator.request()).await.unwrap(),
            None,
            "credential created disabled {operator:?}"
        );
    }
    // One `None`, whichever lever, and for a credential created disabled,
    // in both tenants.
    assert_eq!(nones.len(), (LEVERS.len() + 1) * TENANTS.len());
    assert!(nones.iter().all(|none| none == "Ok(None)"), "{nones:?}");
    drop(conn);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a22_neg_scope_and_role_never_inherit() {
    let (db, pool) = fixture().await;
    let operators = enroll_every_shape(&pool).await;
    let mut hits = 0;
    let mut misses = 0;
    for operator in &operators {
        let key = &operator.credential.public_identity[..];
        for role in ROLES {
            for scope in SCOPES {
                let found = authorize(&pool, &request(key, role, scope)).await.unwrap();
                // Only the operator's own role in its own scope: a tenant
                // binding never in the other tenant or the instance, an
                // instance binding never in a tenant, `security_admin`
                // never for a tenant role, and no role for another.
                if (role, scope) == (operator.binding.role, operator.scope()) {
                    assert_eq!(found, Some(operator.hit()), "{key} {role} {scope:?}");
                    hits += 1;
                } else {
                    assert_eq!(found, None, "{key} {role} {scope:?}");
                    misses += 1;
                }
            }
        }
    }
    assert_eq!(
        (hits, misses),
        (
            SHAPES.len(),
            SHAPES.len() * (ROLES.len() * SCOPES.len() - 1)
        )
    );
    db.drop([pool]).await;
}

/// The lookup has exactly one key, the credential's `public_identity`.
/// Every role and scope shape has an enabled operator, and every other
/// identifier in the same database, used as `public_identity` for every
/// role and every scope, gives `None`: each operator's identity, credential
/// and binding ID; each tenant ID; each tenant's workload actor ID; each
/// tenant's trust source's exact issuer; and an email-shaped name of a human
/// principal of each tenant. This is the registry-level form of "no
/// promotion" (T13.1, API-002): nothing but a registered credential key
/// reaches an operator. It makes no wire claim: no handshake, no endpoint,
/// no upstream token or session is involved (see the module docs).
#[tokio::test]
async fn a22_neg_other_registries_identities_never_authorize() {
    let (db, pool) = fixture().await;
    let operators = enroll_every_shape(&pool).await;
    let mut others: Vec<String> = Vec::new();
    for operator in &operators {
        others.extend([
            operator.identity.id.clone(),
            operator.credential.id.clone(),
            operator.binding.id.clone(),
        ]);
    }
    for tenant in TENANTS {
        others.push(tenant.into());
        let workload = registry::create_principal(
            &pool,
            &NewPrincipal {
                id: format!("wld_{tenant}"),
                tenant_id: tenant.into(),
                kind: PrincipalKind::Workload,
                name: "release".into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        others.push(workload.id);
        let human = registry::create_principal(
            &pool,
            &NewPrincipal {
                id: format!("hum_{tenant}"),
                tenant_id: tenant.into(),
                kind: PrincipalKind::Human,
                name: format!("operator@{tenant}.example"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        assert!(human.name.contains('@'));
        others.push(human.name);
        let issuer = format!("https://idp.example/{tenant}");
        let source = registry::create_trust_source(
            &pool,
            &NewTrustSource {
                id: format!("src_{tenant}"),
                tenant_id: tenant.into(),
                name: "idp".into(),
                kind: TrustSourceKind::OidcDiscovery,
                exact_issuer: issuer.clone(),
                discovery_url: Some(format!("{issuer}/.well-known/openid-configuration")),
                jwks_keyset_id: None,
                cluster_id: None,
                token_review_endpoint: None,
                ca_bundle_ref: None,
                ca_fingerprint: None,
                reviewer_credential_ref: None,
                review_timeout_ms: None,
                audiences: vec!["https://skyoauth.example".into()],
                algorithms: Some(vec!["RS256".into()]),
                proof_bounds: JsonObject::new(),
                assertion_profile: AssertionProfile::ReusableJwt,
                stale_revocation_acknowledged: None,
                replay_mode: ReplayMode::Reusable,
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        others.push(source.exact_issuer);
    }
    assert_eq!(others.len(), 3 * SHAPES.len() + 4 * TENANTS.len());
    // None of them is a registered key.
    for operator in &operators {
        assert!(!others.contains(&operator.credential.public_identity));
    }

    for other in &others {
        for role in ROLES {
            for scope in SCOPES {
                assert_eq!(
                    authorize(&pool, &request(other, role, scope))
                        .await
                        .unwrap(),
                    None,
                    "{other} {role} {scope:?}"
                );
            }
        }
    }
    // Each operator's own key still reaches it.
    for operator in &operators {
        assert_eq!(
            authorize(&pool, &operator.request()).await.unwrap(),
            Some(operator.hit())
        );
    }
    db.drop([pool]).await;
}

/// In one transaction per lever and tenant: the locked lookup returns the
/// plain lookup's hit; after the transaction pulls the lever on the rows
/// the locked lookup holds `FOR SHARE`, both lookups give the same `None`
/// as an unknown key, a wrong scope, a wrong role and the key of an operator
/// of the same tenant whose credential was created `disabled`, in that
/// transaction; and the rollback leaves the hit standing for both.
#[tokio::test]
async fn a22_pos_locked_lookup_equals_the_plain_lookup_and_the_same_none_for_every_lever() {
    let (db, pool) = fixture().await;
    let operators = enroll_one_per_lever(&pool).await;
    let created_disabled = enroll_credential_created_disabled(&pool).await;
    for (lever, operator) in &operators {
        let what = format!("{lever:?} {operator:?}");
        let tenant = operator.binding.tenant_id.as_deref().unwrap();
        let other_tenant = TENANTS.into_iter().find(|t| *t != tenant).unwrap();
        let key = &operator.credential.public_identity[..];
        let disabled = created_disabled
            .iter()
            .find(|o| o.binding.tenant_id == operator.binding.tenant_id)
            .unwrap();
        let misses = [
            request(NEVER_REGISTERED, AdminRole::TrustAdmin, operator.scope()),
            request(
                key,
                AdminRole::TrustAdmin,
                OperatorScope::Tenant(other_tenant),
            ),
            request(key, AdminRole::TrustAdmin, OperatorScope::Instance),
            request(key, AdminRole::ClientAdmin, operator.scope()),
            disabled.request(),
        ];

        let mut tx = pool.begin().await.unwrap();
        let plain = authorize(&mut *tx, &operator.request()).await.unwrap();
        let locked = authorize_operator_locked(&mut tx, &operator.request())
            .await
            .unwrap();
        assert_eq!(plain, Some(operator.hit()), "{what}");
        assert_eq!(locked, plain, "{what}");
        let never = authorize(&mut *tx, &misses[0]).await;
        for miss in &misses {
            let plain = authorize(&mut *tx, miss).await;
            let locked = authorize_operator_locked(&mut tx, miss).await;
            assert_same_none(&plain, &never, &format!("{what}: plain {miss:?}"));
            assert_same_none(&locked, &never, &format!("{what}: locked {miss:?}"));
        }

        lever.pull(&mut tx, operator).await;
        for request in [operator.request()].iter().chain(&misses) {
            let plain = authorize(&mut *tx, request).await;
            let locked = authorize_operator_locked(&mut tx, request).await;
            assert_same_none(&plain, &never, &format!("{what}: plain {request:?}"));
            assert_same_none(&locked, &never, &format!("{what}: locked {request:?}"));
        }
        tx.rollback().await.unwrap();

        // The rollback undid the lever: both lookups hit again.
        let mut tx = pool.begin().await.unwrap();
        let plain = authorize(&mut *tx, &operator.request()).await.unwrap();
        let locked = authorize_operator_locked(&mut tx, &operator.request())
            .await
            .unwrap();
        assert_eq!(plain, Some(operator.hit()), "{what}");
        assert_eq!(locked, plain, "{what}");
        tx.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// A pool that can no longer reach the store gives an `Err` for a request
/// that the store would authorize, not a hit and not a miss; the caller
/// denies it (module docs of `registry::operator`). The plain lookup only:
/// the locked one needs an open transaction, which a closed pool cannot
/// begin.
#[tokio::test]
async fn a22_neg_store_unavailable_is_an_error_not_a_grant() {
    let (db, pool) = fixture().await;
    let mut operators = Vec::new();
    for tenant in TENANTS {
        operators.push(
            enroll(
                &pool,
                &format!("trust_{tenant}"),
                AdminRole::TrustAdmin,
                Some(tenant),
            )
            .await,
        );
    }
    let closed = db.pool().await;
    closed.close().await;
    for operator in &operators {
        let result = authorize(&closed, &operator.request()).await;
        assert!(
            matches!(result, Err(RegistryError::Other(sqlx::Error::PoolClosed))),
            "{result:?}"
        );
        // The store itself would authorize it.
        assert_eq!(
            authorize(&pool, &operator.request()).await.unwrap(),
            Some(operator.hit())
        );
    }
    db.drop([pool, closed]).await;
}
