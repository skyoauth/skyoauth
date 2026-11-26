//! The admin HTTP layer (slice S4 of M1a, dependency-free part): the admin
//! router with the operation reads of D4, the typed peer identity of D5,
//! and the mapping of every admin error family to a status and a stable
//! body (tasks section 13, "M1a lead decisions"; design section 14).
//!
//! It is a module of its own, beside [`crate::admin`], not inside it:
//! [`crate::admin`] is the transport-free service layer (authorized,
//! audited writes that take a presented identity and know nothing of HTTP),
//! and this module is the transport above it and above
//! [`crate::operation`]. Keeping the two apart keeps `axum` out of the
//! service layer and lets a source check say where the router may be named
//! (only here).
//!
//! # Served nowhere (D5)
//!
//! [`admin_router`] is never merged into the plaintext app
//! ([`crate::app`], `127.0.0.1:8080`, API-001) and, until the in-process
//! rustls acceptor lands (S6), nothing serves it: `main` does not name it,
//! and the plaintext app answers 404 for every `/admin` path. Even served by
//! mistake on a plaintext listener it authorizes no one: every handler
//! first extracts the [`AdminPeer`] extension, which only the acceptor sets
//! (and, under `test-support`, the tests' fake acceptor), so every request
//! would be 401. Its routes are the operation reads only:
//!
//! | Method | Path | Readers |
//! | ------ | ---- | ------- |
//! | `GET` | `/admin/v1/operations/{operation}` | instance `security_admin` |
//! | `GET` | `/admin/v1/operations` | instance `security_admin` |
//! | `GET` | `/admin/v1/tenants/{tenant}/operations/{operation}` | instance `security_admin`, the tenant's `auditor`, the requesting `trust_admin` |
//! | `GET` | `/admin/v1/tenants/{tenant}/operations` | the same; a `trust_admin` lists its own only |
//!
//! No write is exposed: none of the twenty-three audited writes of
//! [`crate::admin`] (the twenty workload writes of S3a and the three egress
//! allowlist writes of S2a), not the checker writes, which need the
//! per-algorithm `SubjectPublicKeyInfo` form rule first ([`crate::admin`],
//! "Not done here"), not the tenant create, which needs the IR-034
//! generator, and not the approve, cancel, reject or gated trust writes of
//! [`crate::operation`] and [`crate::trust`]. Later slices add their routes
//! in [`admin_router`] (it says where), each with its error family's
//! mapping below, which is ready for them.
//!
//! # Routes
//!
//! The reads are [`crate::operation::read_operation`] and
//! [`crate::operation::list_operations`]; see their module docs for who may
//! read what. The single read returns an operation in any state; the list
//! returns the open ones (unconsumed, unrevoked, unexpired at the server's
//! clock) by ID byte-wise. A response body is one operation:
//!
//! ```json
//! {"id": "...", "tenant_id": "..." | null, "actor_id": "...",
//!  "kind": "trust_source_create", "request_digest": "<base64url>",
//!  "expected_revision": 3, "expires_at": 1790086400123456,
//!  "plan": "{\"requester_credential_id\":\"...\"}",
//!  "outcome": "pending", "revision": 1}
//! ```
//!
//! or a page, `{"operations": [...], "next": "<last ID>" | null}`, whose
//! `next` is set when the page is full. `plan` is the canonical text the
//! digest preimage embeds, as a string (D29: a plan integer may exceed
//! 2^53), `expires_at` the preimage's integer microseconds, and
//! `request_digest` the stored 32 bytes in unpadded base64url (inferred, as
//! the second-approver proposal, section 2), so a client recomputes the
//! digest from the response alone. A list takes `limit` (default
//! [`operations::DEFAULT_PAGE_SIZE`], clamped to `1..=500` as every
//! registry [`Page`](crate::persistence::registry::Page)) and `after`, the
//! cursor; another query parameter, a repeated one, a `limit` that is not
//! an unsigned 32-bit integer and a cursor with a NUL character are 400
//! `invalid_request` (inferred: the parameter names and the default).
//!
//! Every response of the router carries `Cache-Control: no-store`
//! (inferred: an operation's digest and plan are not for caches, as ERR-051
//! to ERR-053 ask of the other credential-bearing responses). An unknown
//! path or method under the router is 401 without a peer and 404
//! `not_found` with one (inferred). `GET` is the only method of a route:
//! `HEAD`, which `axum` would otherwise answer with the `GET` handler, goes
//! to that same fallback (inferred: a `HEAD` would run the whole read for
//! no body).
//!
//! # Errors
//!
//! Every error body is `{"error":"<code>"}`, `application/json`, and
//! nothing else: no description, no value of the request or of a row (no
//! ID, name, constraint, member or claim name), no key byte, and no
//! version member (ERR-072). Each code has one status. The order of the
//! checks makes the status itself say nothing more than the caller may
//! know: the peer first (401), then a malformed path or query (400) and an
//! unknown path or method (404), which the router answers from the request
//! alone, then the operator's credential (401) and authorization (403),
//! before any target is read, then the target (404, the same bytes for a
//! missing object and for one outside the caller's scope). A 400 or the
//! router's 404 before the authorization tells a caller nothing of the
//! store: both depend on the request's bytes only.
//!
//! **401 versus 403** (ERR-001, ERR-010, ERR-011). 401 `unauthenticated` is
//! a request without a verified peer identity ([`AdminPeer`] absent: no
//! client certificate the acceptor verified), and a verified identity that
//! names no usable credential: none that is enabled and unrevoked, of an
//! enabled operator
//! ([`authenticate_operator`](crate::persistence::registry::authenticate_operator)).
//! A usable credential without a binding of the needed role and scope is
//! 403 `forbidden`, one value for every cause. The two 401s are the same
//! bytes. Telling a 401 from a 403 is no oracle: the peer proved possession
//! of the key in the TLS handshake, so it learns the state of its own
//! credential only. The operation reads split the two
//! ([`OperationReadError`](crate::operation::OperationReadError)); the
//! service-layer writes of [`crate::admin`] still return one
//! `Unauthorized` for both, and the slice that exposes a write must split
//! it the same way before it maps it.
//!
//! The mapping, by family (one pure function each in `error`, an
//! exhaustive `match`, so a new variant fails the build; the unit tests
//! pin each row):
//!
//! | Family | Variant | Status | Code |
//! | ------ | ------- | ------ | ---- |
//! | (request) | no [`AdminPeer`] | 401 | `unauthenticated` |
//! | (request) | malformed path, query or cursor | 400 | `invalid_request` |
//! | (request) | unknown path or method, `HEAD` included | 404 | `not_found` |
//! | [`IdError`](crate::ids::IdError) | `SourceFailed`, `Exhausted` | 500 | `server_error` (D1: writes nothing) |
//! | [`IdentityError`](crate::identity::IdentityError) | every variant | 400 | `invalid_request` |
//! | [`RegistryError`](crate::persistence::registry::RegistryError) | `NotFound` | 404 | `not_found` |
//! | | `StaleRevision` | 409 | `stale_revision` |
//! | | `AlreadyExists`, `Guard` | 409 | `conflict` |
//! | | `Invariant` `Check`, `NotNull` | 400 | `invalid_request` |
//! | | `Invariant` `ForeignKey`, `AssignmentActive`, `EgressEntryEnabled` | 409 | `conflict` |
//! | | `Invariant` `SameTenantOperation`, `DistinctApprover` (tripwires) | 500 | `server_error` |
//! | | `UnreadableTimestamp` | 500 | `server_error` |
//! | | `Retry` (`40001`, `40P01`) | 503 + `Retry-After: 1` | `auth_unavailable` |
//! | | `Other`: `Io`, `Tls`, `PoolTimedOut`, `PoolClosed`; SQLSTATE class `08`, `53`, `57P01` to `57P05` | 503 | `auth_unavailable` |
//! | | `Other`: `55P03`, `57014` (lock or statement timeout) | 503 + `Retry-After: 1` | `auth_unavailable` |
//! | | `Other`: anything else (a decode failure, an unknown SQLSTATE, a constraint not in [`KNOWN_CONSTRAINTS`](crate::persistence::registry::KNOWN_CONSTRAINTS)) | 500 | `server_error` |
//! | | `ReservedActorId`, `RequiredPredicate` | 400 | `invalid_request` |
//! | [`AdminWriteError`](crate::admin::AdminWriteError) | `Unauthorized`, `PrincipalKindNotAllowed` | 403 | `forbidden` |
//! | | `TenantDisabled` | 409 | `tenant_disabled` |
//! | | `InvalidDestination` (a create's submitted destination) | 400 | `invalid_request` |
//! | | `InvalidStoredDestination` (an enable's stored destination) | 409 | `conflict` |
//! | | `WideningNotAcknowledged` | 422 | `widening_not_acknowledged` |
//! | | `SecondApproverRequired` (gate on, no egress operation kind yet) | 409 | `conflict` |
//! | | `PolicyUnavailable` (effectively unreachable: see below) | 503 + `Retry-After: 1` | `auth_unavailable` |
//! | | `UnsupportedIsolation` | 500 | `server_error` |
//! | | `PublicKey(_)`, `Id(_)`, `Registry(_)` | as [`IdentityError`](crate::identity::IdentityError), [`IdError`](crate::ids::IdError), [`RegistryError`](crate::persistence::registry::RegistryError) | |
//! | [`ApprovalError`](crate::operation::ApprovalError) | `Unauthorized`, `SelfApproval` | 403 | `forbidden` |
//! | | `NotFound` | 404 | `not_found` |
//! | | `NotApprovable(_)` (every reason) | 409 | `not_approvable` |
//! | | `EchoMismatch`, `RequesterNotAuthorized` | 409 | `conflict` |
//! | | `StaleRevision` | 409 | `stale_revision` |
//! | | `WideningNotAcknowledged` | 422 | `widening_not_acknowledged` |
//! | | `PlanIntegrity`, `UnsupportedIsolation` | 500 | `server_error` |
//! | | `PolicyUnavailable` | 503 + `Retry-After: 1` | `auth_unavailable` |
//! | | `Keyset(Upload(_))`, `Keyset(PrivateMemberInProvenance)`, `Source(InvalidDestination)` (the stored plan's values) | 409 | `not_approvable` |
//! | | `Registry(Invariant Check, NotNull)`, also inside `Keyset(_)` and `Source(_)` (D7: the constraints run at approve only) | 409 | `not_approvable` |
//! | | any other `Keyset(_)`, `Source(_)`, `Registry(_)` | as their family | |
//! | [`KeysetWriteError`](crate::trust::KeysetWriteError) | `Unauthorized` | 403 | `forbidden` |
//! | | `Upload(_)`, `PrivateMemberInProvenance` | 400 | `invalid_request` |
//! | | `Overlap(_)`, `TooManyEnabledVersions` | 409 | `conflict` |
//! | | `WideningNotAcknowledged` | 422 | `widening_not_acknowledged` |
//! | | `StoredVersion`, `StoredFingerprintMismatch`, `UnsupportedIsolation` | 500 | `server_error` |
//! | | `WorkerUnavailable` | 503 | `auth_unavailable` |
//! | | `ValidationBusy`, `PolicyUnavailable` | 503 + `Retry-After: 1` | `auth_unavailable` |
//! | | `Registry(_)` | as [`RegistryError`](crate::persistence::registry::RegistryError) | |
//! | [`SourceWriteError`](crate::trust::SourceWriteError) | `Unauthorized` | 403 | `forbidden` |
//! | | `InvalidDestination` | 400 | `invalid_request` |
//! | | `EgressNotAllowed` | 409 | `conflict` |
//! | | `WideningNotAcknowledged` | 422 | `widening_not_acknowledged` |
//! | | `UnsupportedIsolation` | 500 | `server_error` |
//! | | `PolicyUnavailable` | 503 + `Retry-After: 1` | `auth_unavailable` |
//! | | `Registry(_)` | as [`RegistryError`](crate::persistence::registry::RegistryError) | |
//! | [`OperationReadError`](crate::operation::OperationReadError) | `Unauthenticated` (no usable credential) | 401 | `unauthenticated` |
//! | | `Unauthorized` | 403 | `forbidden` |
//! | | `NotFound` | 404 | `not_found` |
//! | | `PlanIntegrity` | 500 | `server_error` |
//! | | `Registry(_)` | as [`RegistryError`](crate::persistence::registry::RegistryError) | |
//!
//! The classes, which a variant of a later family follows: 400 for a
//! request or a submitted value that breaks a syntax or value rule,
//! whatever the stored state (a value the request did not submit, a stored
//! plan's or a stored row's, is the stored state's: 409); 422 only for a
//! well-formed write that lacks the widening acknowledgement the server's
//! rule asks for (the second-approver proposal's mapping, section 10); 409
//! for a refusal by the stored state (a moved revision, a duplicate, a
//! missing or disabled referenced row, a disabled tenant, an operation that
//! is no longer approvable, a stored plan or destination a check refuses);
//! 401 for a peer or credential that authenticates no one; 403 for a
//! refusal of the
//! caller's authority, an `PrincipalKindNotAllowed` included (inferred:
//! IR-043 limits what this path's authority reaches, ERR-011); 500 for a
//! server or data-integrity error, where nothing was written; 503 for an
//! unavailable store or worker, with `Retry-After` when a retry of the
//! whole request may succeed (the proposal's mapping).
//!
//! `PolicyUnavailable` (no instance security policy row, D18) is effectively
//! unreachable after the authorization: bootstrap writes the policy row in
//! the transaction that enrolls the first operator, so before it no
//! credential authorizes anything. It keeps its retryable 503 (a store
//! state that never widens) rather than a 500.
//!
//! This is the proposed mapping of the S4 PR (lead decision, 2026-11-24,
//! "the admin error-to-HTTP mapping is proposed in the S4 PR"); every row
//! not quoted from the proposal is inferred.
//!
//! # Wire codes
//!
//! Reused: `unauthenticated`, `forbidden` and `auth_unavailable`, the
//! frozen reasons of errors-retry section 2 (ERR-070; the admin store
//! outage is the "store outage" of `auth_unavailable`), and
//! `invalid_request` and `server_error`, the OAuth `error` values
//! (RFC 6749). Proposed here, since no catalogue names them yet
//! (`tests/conformance/fixtures/_wire/errors.v1.json` does not exist):
//! `not_found`, `stale_revision`, `conflict`, `not_approvable`,
//! `tenant_disabled` and `widening_not_acknowledged`.

mod error;
mod operations;
mod peer;

use std::sync::Arc;

use axum::{
    Router,
    http::{HeaderValue, header},
    middleware::map_response,
    response::Response,
    routing::get,
};

pub use error::{
    AdminHttpError, ErrorCode, RETRY_AFTER_SECONDS, from_admin_write, from_approval, from_id,
    from_identity, from_keyset_write, from_operation_read, from_registry, from_source_write,
};
pub use operations::DEFAULT_PAGE_SIZE;
pub use peer::AdminPeer;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use peer::test_support;

use crate::operation::Clock;
use crate::persistence::PgPool;

/// `GET`: one page of the open instance operations.
pub const INSTANCE_OPERATIONS: &str = "/admin/v1/operations";
/// `GET`: one instance operation.
pub const INSTANCE_OPERATION: &str = "/admin/v1/operations/{operation}";
/// `GET`: one page of the open operations of `{tenant}`.
pub const TENANT_OPERATIONS: &str = "/admin/v1/tenants/{tenant}/operations";
/// `GET`: one operation of `{tenant}`.
pub const TENANT_OPERATION: &str = "/admin/v1/tenants/{tenant}/operations/{operation}";

/// Every route of [`admin_router`], all `GET`.
pub const ADMIN_ROUTES: [&str; 4] = [
    INSTANCE_OPERATIONS,
    INSTANCE_OPERATION,
    TENANT_OPERATIONS,
    TENANT_OPERATION,
];

/// What the admin handlers share: the pool and the clock of a list's
/// "open at now".
#[derive(Clone)]
pub struct AdminState {
    pool: PgPool,
    clock: Arc<dyn Clock + Send>,
}

impl AdminState {
    pub fn new(pool: PgPool, clock: Arc<dyn Clock + Send>) -> Self {
        Self { pool, clock }
    }
}

/// The admin router (see the module docs): the operation reads of D4, and
/// nothing else yet. Never merged into [`crate::app`]; served nowhere until
/// the rustls acceptor lands (D5). A route's `HEAD` is the fallback's, not
/// its `GET` handler's.
pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        .route(
            INSTANCE_OPERATIONS,
            get(operations::list_instance).head(unknown),
        )
        .route(
            INSTANCE_OPERATION,
            get(operations::read_instance).head(unknown),
        )
        .route(
            TENANT_OPERATIONS,
            get(operations::list_tenant).head(unknown),
        )
        .route(TENANT_OPERATION, get(operations::read_tenant).head(unknown))
        // Later slices add their routes here, each listed in ADMIN_ROUTES
        // and the module docs, its handler extracting `AdminPeer` first.
        .fallback(unknown)
        .method_not_allowed_fallback(unknown)
        .with_state(state)
        .layer(map_response(no_store))
}

/// An unknown path or method, and a route's `HEAD`: 401 without a peer,
/// else 404.
async fn unknown(_: AdminPeer) -> AdminHttpError {
    AdminHttpError::NOT_FOUND
}

/// Sets `Cache-Control: no-store` on every response of the router.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode},
    };
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tower::ServiceExt;

    use super::*;
    use crate::operation::SystemClock;

    /// A pool that never connects: these tests never reach the store.
    fn state() -> AdminState {
        let options = PgConnectOptions::new().host("127.0.0.1").port(1);
        let pool = PgPoolOptions::new().connect_lazy_with(options);
        AdminState::new(pool, Arc::new(SystemClock))
    }

    /// Each route with its parameters filled in, and other `/admin` paths.
    fn admin_paths() -> Vec<String> {
        let mut paths: Vec<String> = ADMIN_ROUTES
            .iter()
            .map(|route| {
                route
                    .replace("{tenant}", "ten_a")
                    .replace("{operation}", "op_1")
            })
            .collect();
        paths.extend(
            [
                "/admin",
                "/admin/",
                "/admin/v1",
                "/admin/v1/tenants",
                "/admin/v1/tenants/ten_a",
                "/admin/v1/operations/op_1/approve",
                "/admin/v1/tenants/ten_a/operations/op_1/approve",
                "/admin/v1/tenants/ten_a/operations/op_1/cancel",
                "/admin/v1/resource-servers",
                "/admin/v1/instance-security-policy",
            ]
            .map(String::from),
        );
        paths
    }

    const METHODS: [Method; 6] = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PATCH,
        Method::PUT,
        Method::DELETE,
    ];

    fn request(method: &Method, path: &str, peer: bool) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("x-client-cert", "spki-sha256:spoofed")
            .body(Body::empty())
            .unwrap();
        if peer {
            let peer = AdminPeer::from_peer_spki(&[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x51, 0xf4,
                0x58, 0x9a, 0x4c, 0xc7, 0x8f, 0xa1, 0xb0, 0xb8, 0xb6, 0x2c, 0x23, 0xeb, 0x53, 0x90,
                0x68, 0x97, 0x4c, 0x29, 0xee, 0x0c, 0x6a, 0x22, 0x94, 0x40, 0x51, 0x8d, 0x91, 0x63,
                0xf0, 0xe4,
            ])
            .unwrap();
            request.extensions_mut().insert(peer);
        }
        request
    }

    /// The plaintext app serves no admin path, for any method, also when
    /// the request carries a peer extension.
    #[tokio::test]
    async fn the_plaintext_app_answers_404_for_every_admin_path() {
        for path in admin_paths() {
            for method in &METHODS {
                for peer in [false, true] {
                    let response = crate::app()
                        .oneshot(request(method, &path, peer))
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
                }
            }
        }
    }

    /// Without a peer, every path and method of the admin router is 401
    /// `unauthenticated` with `no-store`, before the store is reached.
    #[tokio::test]
    async fn the_admin_router_answers_401_without_a_peer() {
        for path in admin_paths() {
            for method in &METHODS {
                let response = admin_router(state())
                    .oneshot(request(method, &path, false))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {path}"
                );
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let body = to_bytes(response.into_body(), 1024).await.unwrap();
                // A `HEAD` response has no body.
                if method == Method::HEAD {
                    assert_eq!(body, "", "{path}");
                } else {
                    assert_eq!(body, "{\"error\":\"unauthenticated\"}");
                }
            }
        }
    }

    /// With a peer, an unknown path or method, and a route's `HEAD`, is 404
    /// `not_found`, before the store is reached; a malformed query is 400.
    #[tokio::test]
    async fn unknown_paths_and_bad_queries_need_no_store() {
        let unknown = [
            (Method::GET, "/admin"),
            (Method::GET, "/admin/v1/tenants/ten_a"),
            (Method::POST, "/admin/v1/operations/op_1/approve"),
            (Method::POST, "/admin/v1/operations"),
            (Method::DELETE, "/admin/v1/tenants/ten_a/operations/op_1"),
            (Method::PATCH, "/admin/v1/tenants/ten_a/operations"),
        ];
        let heads = ADMIN_ROUTES.map(|route| {
            (
                Method::HEAD,
                route
                    .replace("{tenant}", "ten_a")
                    .replace("{operation}", "op_1"),
            )
        });
        for (method, path) in heads {
            // The `GET` handler would reach the store, which this pool never
            // connects to (a 503); the fallback answers 404 before it.
            let response = admin_router(state())
                .oneshot(request(&method, &path, true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        }
        for (method, path) in unknown {
            let response = admin_router(state())
                .oneshot(request(&method, path, true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(body, "{\"error\":\"not_found\"}");
        }
        for query in [
            "limit=x",
            "limit=-1",
            "limit=4294967296",
            "after=a&after=b",
            "after=a%00b",
            "cursor=a",
            "limit=1&tenant=ten_b",
        ] {
            for path in ["/admin/v1/operations", "/admin/v1/tenants/ten_a/operations"] {
                let uri = format!("{path}?{query}");
                let response = admin_router(state())
                    .oneshot(request(&Method::GET, &uri, true))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
                let body = to_bytes(response.into_body(), 1024).await.unwrap();
                assert_eq!(body, "{\"error\":\"invalid_request\"}");
            }
        }
        let response = admin_router(state())
            .oneshot(request(&Method::GET, "/admin/v1/operations/%FF", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
