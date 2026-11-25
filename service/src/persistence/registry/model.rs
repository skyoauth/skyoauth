//! Typed rows of the registry tables and the inputs of their writes.

use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sqlx::{
    FromRow, Row,
    postgres::{PgRow, types::PgInterval},
    types::Json,
};

use super::{UNREADABLE_MICROSECONDS, error::UnreadableTimestamp};

/// A `jsonb` column the schema requires to be an object.
pub type JsonObject = Map<String, Value>;

/// A text value that is not one of an enumeration's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownValue {
    type_name: &'static str,
}

impl fmt::Display for UnknownValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a {} value", self.type_name)
    }
}

impl StdError for UnknownValue {}

/// A text enumeration column: `as_str` gives the stored value, `FromStr`
/// parses it.
macro_rules! text_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$variant_meta:meta])* $variant:ident = $text:literal,)+ }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// The value as stored in the database.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        impl FromStr for $name {
            type Err = UnknownValue;

            fn from_str(value: &str) -> Result<Self, UnknownValue> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(UnknownValue { type_name: stringify!($name) }),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

text_enum! {
    /// The `status` of every registry row (`enabled` or `disabled`).
    Status {
        /// `enabled`.
        Enabled = "enabled",
        /// `disabled`.
        Disabled = "disabled",
    }
}

text_enum! {
    /// `principal.kind` (identity-registry section 5.1).
    PrincipalKind {
        /// `human`.
        Human = "human",
        /// `workload`.
        Workload = "workload",
        /// `service`.
        Service = "service",
    }
}

text_enum! {
    /// A credential profile, an element of the `skyoauth_profile_list`
    /// columns (token-profiles section 3).
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    Profile {
        /// `wif`.
        Wif = "wif",
        /// `human_cli`.
        HumanCli = "human_cli",
        /// `human_session`.
        HumanSession = "human_session",
    }
}

text_enum! {
    /// `egress_allowlist_entry.purpose` (IR-152).
    EgressPurpose {
        /// `oidc_discovery`.
        OidcDiscovery = "oidc_discovery",
        /// `jwks`.
        Jwks = "jwks",
        /// `token_review`.
        TokenReview = "token_review",
    }
}

text_enum! {
    /// `trust_source.kind` (ADR-005; tasks section 3 "Source kinds").
    TrustSourceKind {
        /// `oidc_discovery`: keys from the issuer's discovery document.
        OidcDiscovery = "oidc_discovery",
        /// `uploaded_jwks`: keys from a tenant-owned trust keyset.
        UploadedJwks = "uploaded_jwks",
        /// `kubernetes_token_review`: a cluster's TokenReview API.
        KubernetesTokenReview = "kubernetes_token_review",
    }
}

text_enum! {
    /// `trust_source.assertion_profile` (OQ-ADR005-2).
    AssertionProfile {
        /// `on_demand_jwt`.
        OnDemandJwt = "on_demand_jwt",
        /// `reusable_jwt`.
        ReusableJwt = "reusable_jwt",
        /// `projected_service_account`.
        ProjectedServiceAccount = "projected_service_account",
    }
}

text_enum! {
    /// `trust_source.replay_mode` (OQ-ADR005-2; ADR-016 items 6 and 8).
    ReplayMode {
        /// `reusable`.
        Reusable = "reusable",
        /// `single_use`.
        SingleUse = "single_use",
    }
}

text_enum! {
    /// `principal_binding.profile`, the template that fixes the required
    /// predicates (ADR-016 item 4; the three values taken as the whole set,
    /// inferred in `0004`).
    BindingProfile {
        /// `github_production`.
        GithubProduction = "github_production",
        /// `kubernetes_production`.
        KubernetesProduction = "kubernetes_production",
        /// `generic_production`.
        GenericProduction = "generic_production",
    }
}

text_enum! {
    /// `service_grant.mode` (OQ-ADR006-1).
    GrantMode {
        /// `direct`: no target service.
        Direct = "direct",
        /// `delegation`: a same-tenant target service.
        Delegation = "delegation",
        /// `impersonation`: a same-tenant target service, stored only
        /// disabled and requiring reapproval.
        Impersonation = "impersonation",
    }
}

text_enum! {
    /// `service_grant.activation_state` (OQ-ADR006-1).
    ActivationState {
        /// `not_required`.
        NotRequired = "not_required",
        /// `requires_reapproval`, exactly for impersonation grants.
        RequiresReapproval = "requires_reapproval",
    }
}

text_enum! {
    /// `admin_role_binding.role` (identity-registry section 5.2). No role
    /// implies another (public-api API-120).
    AdminRole {
        /// `security_admin`, instance only.
        SecurityAdmin = "security_admin",
        /// `trust_admin`, tenant only.
        TrustAdmin = "trust_admin",
        /// `client_admin`, tenant only.
        ClientAdmin = "client_admin",
        /// `provider_admin`, tenant only.
        ProviderAdmin = "provider_admin",
        /// `auditor`, of one tenant or of the instance.
        Auditor = "auditor",
    }
}

/// Reads a text enumeration column.
pub(super) fn text<T: FromStr<Err = UnknownValue>>(
    row: &PgRow,
    column: &str,
) -> Result<T, sqlx::Error> {
    row.try_get::<&str, _>(column)?
        .parse()
        .map_err(|source: UnknownValue| sqlx::Error::ColumnDecode {
            index: column.into(),
            source: source.into(),
        })
}

/// Reads a `jsonb` column.
pub(super) fn json<T: DeserializeOwned>(row: &PgRow, column: &str) -> Result<T, sqlx::Error> {
    Ok(row.try_get::<Json<T>, _>(column)?.0)
}

/// Reads a nullable `jsonb` column.
pub(super) fn optional_json<T: DeserializeOwned>(
    row: &PgRow,
    column: &str,
) -> Result<Option<T>, sqlx::Error> {
    Ok(row
        .try_get::<Option<Json<T>>, _>(column)?
        .map(|json| json.0))
}

/// PostgreSQL's earliest `timestamptz`, 4713 BC in the Julian calendar
/// (`4714-11-24 00:00:00+00 BC` in PostgreSQL's proleptic Gregorian
/// output), in microseconds from the Unix epoch. One microsecond earlier
/// fails inside the statement with `22008` (`datetime_field_overflow`).
const EARLIEST_MICROSECONDS: i64 = -210_866_803_200_000_000;

/// The latest time the registry writes, in microseconds from the Unix
/// epoch: `i64::MAX - 1`, `294247-01-10 04:00:54.775806+00`. PostgreSQL's
/// own latest `timestamptz`, `294276-12-31 23:59:59.999999+00`, is
/// `9_224_318_015_999_999_999` microseconds, beyond `i64::MAX`, so it is
/// not the bound. `i64::MAX` itself is excluded: PostgreSQL 16 computes
/// `extract(epoch FROM ...)` of exactly that time through a rounding
/// division, so it would read back as `9_223_372_036_854_775_800`.
const LATEST_MICROSECONDS: i64 = i64::MAX - 1;

/// `time` truncated toward the past to a whole microsecond, the time the
/// registry stores for it (inferred). [`since_epoch`] floors through it, and
/// a check that must see the stored time before the write (the overlap
/// check of [`crate::trust::keyset`]) floors through it too, so the two
/// cannot disagree. A time whose floor the platform cannot represent is
/// returned as is: it is far outside the range [`since_epoch`] accepts.
pub(crate) fn floor_to_microsecond(time: SystemTime) -> SystemTime {
    let excess = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.subsec_nanos() % 1000,
        Err(before) => (1000 - before.duration().subsec_nanos() % 1000) % 1000,
    };
    time.checked_sub(Duration::from_nanos(u64::from(excess)))
        .unwrap_or(time)
}

/// The microseconds from the Unix epoch to `time`, truncated toward the
/// past (inferred, through [`floor_to_microsecond`]), as an interval a
/// statement adds to `timestamptz 'epoch'`, so the crate needs no date-time
/// dependency and the conversion stays in integers.
///
/// A time before [`EARLIEST_MICROSECONDS`] or after
/// [`LATEST_MICROSECONDS`] is an encode error, mapped to
/// [`RegistryError::Other`](super::RegistryError::Other), before any
/// statement runs, so every time the registry writes reads back exactly.
pub(super) fn since_epoch(time: SystemTime) -> Result<PgInterval, sqlx::Error> {
    let microseconds = match floor_to_microsecond(time).duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_micros()).ok(),
        Err(before) => i64::try_from(before.duration().as_micros())
            .ok()
            .map(|micros| -micros),
    };
    microseconds
        .filter(|microseconds| (EARLIEST_MICROSECONDS..=LATEST_MICROSECONDS).contains(microseconds))
        .map(|microseconds| PgInterval {
            months: 0,
            days: 0,
            microseconds,
        })
        .ok_or_else(|| sqlx::Error::Encode("timestamp out of range".into()))
}

/// [`since_epoch`] of an optional time.
pub(super) fn optional_since_epoch(
    time: Option<SystemTime>,
) -> Result<Option<PgInterval>, sqlx::Error> {
    time.map(since_epoch).transpose()
}

/// Where a row came from, for [`UnreadableTimestamp`]: its table and the
/// column holding its ID.
#[derive(Clone, Copy)]
pub(super) struct Origin {
    table: &'static str,
    id_column: &'static str,
}

impl Origin {
    pub(super) const fn new(table: &'static str) -> Self {
        Self {
            table,
            id_column: "id",
        }
    }
}

/// Reads the timestamp `column`, which the query selected with
/// [`micros!`](super::micros) as `<column>_us`, microseconds since the Unix
/// epoch, so the crate needs no date-time dependency (inferred). A time
/// outside the readable range is an [`UnreadableTimestamp`] naming the row.
pub(super) fn timestamp(
    row: &PgRow,
    origin: Origin,
    column: &'static str,
) -> Result<Option<SystemTime>, sqlx::Error> {
    let index = format!("{column}_us");
    let Some(micros) = row.try_get::<Option<i64>, _>(&index[..])? else {
        return Ok(None);
    };
    if micros == UNREADABLE_MICROSECONDS {
        return Err(sqlx::Error::ColumnDecode {
            index,
            source: Box::new(UnreadableTimestamp {
                table: origin.table,
                column,
                id: row.try_get(origin.id_column)?,
            }),
        });
    }
    let offset = Duration::from_micros(micros.unsigned_abs());
    let time = if micros >= 0 {
        UNIX_EPOCH.checked_add(offset)
    } else {
        UNIX_EPOCH.checked_sub(offset)
    };
    time.map(Some).ok_or_else(|| sqlx::Error::ColumnDecode {
        index,
        source: "timestamp out of range".into(),
    })
}

/// Reads a `NOT NULL` timestamp selected as [`timestamp`] expects.
pub(super) fn required_timestamp(
    row: &PgRow,
    origin: Origin,
    column: &'static str,
) -> Result<SystemTime, sqlx::Error> {
    timestamp(row, origin, column)?.ok_or_else(|| sqlx::Error::ColumnDecode {
        index: format!("{column}_us"),
        source: "unexpected NULL".into(),
    })
}

/// A tenant (identity-registry IR-030..IR-034).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    /// Mutable and not unique (`0002` has no unique constraint on it).
    pub name: String,
    /// Unique, immutable and server-generated (IR-034).
    pub secret_namespace: String,
    pub status: Status,
    /// Immutable.
    pub created_at: SystemTime,
    /// Added by `0007`.
    pub revision: i64,
}

impl FromRow<'_, PgRow> for Tenant {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("tenant");
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            secret_namespace: row.try_get("secret_namespace")?,
            status: text(row, "status")?,
            created_at: required_timestamp(row, ORIGIN, "created_at")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_tenant` (called by
/// `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`). `created_at` is set by the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTenant {
    pub id: String,
    pub name: String,
    pub secret_namespace: String,
    pub status: Status,
}

/// The columns the crate-private `update_tenant` changes (called by
/// `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`): each one that is set (lead ruling,
/// 2026-11-21). At least one must be set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantPatch {
    pub name: Option<String>,
    pub status: Option<Status>,
}

impl TenantPatch {
    /// Whether no column is set.
    pub(super) fn is_empty(&self) -> bool {
        self.name.is_none() && self.status.is_none()
    }
}

/// A principal of a tenant (identity-registry section 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    /// Immutable.
    pub tenant_id: String,
    /// Immutable.
    pub kind: PrincipalKind,
    /// Mutable, and unique within the tenant and kind, disabled principals
    /// included (`0002` `principal_tenant_id_kind_name_key`; IR-021). Holds
    /// no control character (`principal_name_no_control_check`), TAB, LF,
    /// VT, FF and CR included; spaces that are not controls have no rule.
    /// May hold format characters such as U+202E and the separators U+2028
    /// and U+2029, which a display surface escapes.
    pub name: String,
    pub status: Status,
    /// Immutable.
    pub created_at: SystemTime,
    /// Added by `0007`.
    pub revision: i64,
}

impl FromRow<'_, PgRow> for Principal {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("principal");
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            kind: text(row, "kind")?,
            name: row.try_get("name")?,
            status: text(row, "status")?,
            created_at: required_timestamp(row, ORIGIN, "created_at")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_principal` (called by
/// `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrincipal {
    pub id: String,
    pub tenant_id: String,
    pub kind: PrincipalKind,
    pub name: String,
    pub status: Status,
}

/// The columns the crate-private `update_principal` changes (called by
/// `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`): each one that is set (lead ruling,
/// 2026-11-21). At least one must be set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrincipalPatch {
    pub name: Option<String>,
    pub status: Option<Status>,
}

impl PrincipalPatch {
    /// Whether no column is set.
    pub(super) fn is_empty(&self) -> bool {
        self.name.is_none() && self.status.is_none()
    }
}

/// A resource server (IR-070, IR-071).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServer {
    pub id: String,
    /// Globally unique and immutable.
    pub audience: String,
    pub name: String,
    pub allowed_profiles: Vec<Profile>,
    pub scopes: Vec<String>,
    /// The element type is open (OQ-TP-7), so elements are any JSON value.
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for ResourceServer {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            audience: row.try_get("audience")?,
            name: row.try_get("name")?,
            allowed_profiles: json(row, "allowed_profiles")?,
            scopes: json(row, "scopes")?,
            constraint_versions: json(row, "constraint_versions")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_resource_server` (called by
/// `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewResourceServer {
    pub id: String,
    pub audience: String,
    pub name: String,
    pub allowed_profiles: Vec<Profile>,
    pub scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
}

/// The mutable columns of a resource server, all replaced by the
/// crate-private `update_resource_server` (called by `crate::admin`; tests
/// reach it through the `test-support` feature's `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerChanges {
    pub name: String,
    pub allowed_profiles: Vec<Profile>,
    pub scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
}

/// An audience assignment of one tenant (IR-080..IR-083; ADR-018 items 3
/// and 4). Instance authority, so it is read by its own ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceTenantAssignment {
    pub id: String,
    pub resource_server_id: String,
    pub tenant_id: String,
    pub allowed_profiles: Vec<Profile>,
    pub allowed_scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for AudienceTenantAssignment {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            resource_server_id: row.try_get("resource_server_id")?,
            tenant_id: row.try_get("tenant_id")?,
            allowed_profiles: json(row, "allowed_profiles")?,
            allowed_scopes: json(row, "allowed_scopes")?,
            constraint_versions: json(row, "constraint_versions")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_audience_tenant_assignment`
/// (called by `crate::admin`; tests reach it through the `test-support`
/// feature's `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAudienceTenantAssignment {
    pub id: String,
    pub resource_server_id: String,
    pub tenant_id: String,
    pub allowed_profiles: Vec<Profile>,
    pub allowed_scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
}

/// The mutable columns of an assignment, all replaced by the crate-private
/// `update_audience_tenant_assignment` (called by `crate::admin`; tests
/// reach it through the `test-support` feature's `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceTenantAssignmentChanges {
    pub allowed_profiles: Vec<Profile>,
    pub allowed_scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
}

/// A checker identity of one resource server (IR-090; ADR-018 item 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerChecker {
    pub id: String,
    pub resource_server_id: String,
    pub public_mtls_identity: String,
    /// The tenants of its rows in `resource_server_checker_tenant`, sorted
    /// byte-wise. Every listed tenant has an assignment of the checker's
    /// resource server, whatever its status: leaving out a tenant whose
    /// assignment is disabled is the caller's rule (OQ-ADR018-1).
    pub allowed_tenant_ids: Vec<String>,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for ResourceServerChecker {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            resource_server_id: row.try_get("resource_server_id")?,
            public_mtls_identity: row.try_get("public_mtls_identity")?,
            allowed_tenant_ids: row.try_get("allowed_tenant_ids")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_resource_server_checker` (called
/// by `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`). The checker starts with no tenants; see
/// `add_resource_server_checker_tenant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewResourceServerChecker {
    pub id: String,
    pub resource_server_id: String,
    pub public_mtls_identity: String,
    pub status: Status,
}

/// The mutable columns of a checker, all replaced by the crate-private
/// `update_resource_server_checker` (called by `crate::admin`; tests reach
/// it through the `test-support` feature's `registry::test_support`). The
/// identity may be rotated (inferred in `0003`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerCheckerChanges {
    pub public_mtls_identity: String,
    pub status: Status,
}

/// An action rule of a resource server, M1a fields (IR-100, IR-104).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAction {
    pub id: String,
    pub resource_server_id: String,
    pub action_name: String,
    pub required_scopes: Vec<String>,
    pub accepted_profiles: Vec<Profile>,
    pub required_resource_dimensions: Vec<String>,
    pub live_check_required: bool,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for ResourceAction {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            resource_server_id: row.try_get("resource_server_id")?,
            action_name: row.try_get("action_name")?,
            required_scopes: json(row, "required_scopes")?,
            accepted_profiles: json(row, "accepted_profiles")?,
            required_resource_dimensions: json(row, "required_resource_dimensions")?,
            live_check_required: row.try_get("live_check_required")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_resource_action` (called by
/// `crate::admin`; tests reach it through the `test-support` feature's
/// `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewResourceAction {
    pub id: String,
    pub resource_server_id: String,
    pub action_name: String,
    pub required_scopes: Vec<String>,
    pub accepted_profiles: Vec<Profile>,
    pub required_resource_dimensions: Vec<String>,
    pub live_check_required: bool,
    pub status: Status,
}

/// The mutable columns of an action rule, all replaced by the
/// crate-private `update_resource_action` (called by `crate::admin`; tests
/// reach it through the `test-support` feature's `registry::test_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceActionChanges {
    pub required_scopes: Vec<String>,
    pub accepted_profiles: Vec<Profile>,
    pub required_resource_dimensions: Vec<String>,
    pub live_check_required: bool,
    pub status: Status,
}

/// The instance security policy, one row per instance (IR-052, IR-053).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSecurityPolicy {
    pub instance_id: String,
    pub widening_second_approver: bool,
    pub single_actor_mode: bool,
    pub audit_sink_config_digest: Option<Vec<u8>>,
    pub audit_sink_validated_at: Option<SystemTime>,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for InstanceSecurityPolicy {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            instance_id: row.try_get("instance_id")?,
            widening_second_approver: row.try_get("widening_second_approver")?,
            single_actor_mode: row.try_get("single_actor_mode")?,
            audit_sink_config_digest: row.try_get("audit_sink_config_digest")?,
            audit_sink_validated_at: timestamp(
                row,
                Origin {
                    table: "instance_security_policy",
                    id_column: "instance_id",
                },
                "audit_sink_validated_at",
            )?,
            revision: row.try_get("revision")?,
        })
    }
}

/// An exact egress destination (IR-152).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressAllowlistEntry {
    pub id: String,
    pub purpose: EgressPurpose,
    pub exact_destination: String,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for EgressAllowlistEntry {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            purpose: text(row, "purpose")?,
            exact_destination: row.try_get("exact_destination")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// A trust keyset, the stable tenant-owned parent of uploaded key versions
/// (ADR-005 item 5; T11.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustKeyset {
    pub id: String,
    pub tenant_id: String,
    /// Unique within the tenant.
    pub name: String,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for TrustKeyset {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the registry-private `create_trust_keyset` (tests reach it
/// through the `test-support` feature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTrustKeyset {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub status: Status,
}

/// The mutable columns of a keyset, all replaced by the registry-private
/// `update_trust_keyset` (tests only, through the `test-support` feature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustKeysetChanges {
    pub name: String,
    pub status: Status,
}

/// A public-only key version of a keyset (ADR-005 item 5; T11.3),
/// immutable but for `status`.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustKeysetVersion {
    pub id: String,
    pub tenant_id: String,
    pub keyset_id: String,
    /// A JWK Set whose `keys` is a nonempty array of objects without a
    /// private or symmetric key member.
    pub public_jwks: JsonObject,
    pub fingerprint: String,
    pub effective_at: SystemTime,
    /// After `effective_at` when set.
    pub expires_at: Option<SystemTime>,
    /// The one mutable column.
    pub status: Status,
    pub provenance: JsonObject,
    /// The version's own revision, added by `0007`, not tied to the
    /// keyset's.
    pub revision: i64,
}

impl FromRow<'_, PgRow> for TrustKeysetVersion {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("trust_keyset_version");
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            keyset_id: row.try_get("keyset_id")?,
            public_jwks: json(row, "public_jwks")?,
            fingerprint: row.try_get("fingerprint")?,
            effective_at: required_timestamp(row, ORIGIN, "effective_at")?,
            expires_at: timestamp(row, ORIGIN, "expires_at")?,
            status: text(row, "status")?,
            provenance: json(row, "provenance")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_trust_keyset_version`, the
/// keyset version write's registry floor (tests reach it through the
/// `test-support` feature).
#[derive(Debug, Clone, PartialEq)]
pub struct NewTrustKeysetVersion {
    pub id: String,
    pub tenant_id: String,
    pub keyset_id: String,
    pub public_jwks: JsonObject,
    pub fingerprint: String,
    pub effective_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub status: Status,
    pub provenance: JsonObject,
}

/// A trust source (ADR-005; identity-registry IR-032, IR-151). The columns
/// are flat: `kind` decides which of the optional fields are set, and the
/// database enforces it with the named `trust_source_*_kind_check`s
/// (migrations README, "What 0004 adds").
#[derive(Debug, Clone, PartialEq)]
pub struct TrustSource {
    pub id: String,
    pub tenant_id: String,
    /// Unique within the tenant.
    pub name: String,
    /// Immutable.
    pub kind: TrustSourceKind,
    /// Compared exactly; not unique (IR-032).
    pub exact_issuer: String,
    /// Set exactly for [`TrustSourceKind::OidcDiscovery`].
    pub discovery_url: Option<String>,
    /// Set exactly for [`TrustSourceKind::UploadedJwks`]; immutable.
    pub jwks_keyset_id: Option<String>,
    /// Set exactly for [`TrustSourceKind::KubernetesTokenReview`], as are the
    /// five fields after it; unique across sources and immutable.
    pub cluster_id: Option<String>,
    pub token_review_endpoint: Option<String>,
    pub ca_bundle_ref: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub reviewer_credential_ref: Option<String>,
    pub review_timeout_ms: Option<i32>,
    /// Nonempty.
    pub audiences: Vec<String>,
    /// Nonempty when set; set exactly for the kinds that verify locally.
    pub algorithms: Option<Vec<String>>,
    pub proof_bounds: JsonObject,
    pub assertion_profile: AssertionProfile,
    /// `Some(true)` exactly for projected service-account tokens verified
    /// locally (IR-151).
    pub stale_revocation_acknowledged: Option<bool>,
    pub replay_mode: ReplayMode,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for TrustSource {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            kind: text(row, "kind")?,
            exact_issuer: row.try_get("exact_issuer")?,
            discovery_url: row.try_get("discovery_url")?,
            jwks_keyset_id: row.try_get("jwks_keyset_id")?,
            cluster_id: row.try_get("cluster_id")?,
            token_review_endpoint: row.try_get("token_review_endpoint")?,
            ca_bundle_ref: row.try_get("ca_bundle_ref")?,
            ca_fingerprint: row.try_get("ca_fingerprint")?,
            reviewer_credential_ref: row.try_get("reviewer_credential_ref")?,
            review_timeout_ms: row.try_get("review_timeout_ms")?,
            audiences: json(row, "audiences")?,
            algorithms: optional_json(row, "algorithms")?,
            proof_bounds: json(row, "proof_bounds")?,
            assertion_profile: text(row, "assertion_profile")?,
            stale_revocation_acknowledged: row.try_get("stale_revocation_acknowledged")?,
            replay_mode: text(row, "replay_mode")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the crate-private `create_trust_source`, the trust source
/// write's registry floor (tests reach it through the `test-support`
/// feature).
#[derive(Debug, Clone, PartialEq)]
pub struct NewTrustSource {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub kind: TrustSourceKind,
    pub exact_issuer: String,
    pub discovery_url: Option<String>,
    pub jwks_keyset_id: Option<String>,
    pub cluster_id: Option<String>,
    pub token_review_endpoint: Option<String>,
    pub ca_bundle_ref: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub reviewer_credential_ref: Option<String>,
    pub review_timeout_ms: Option<i32>,
    pub audiences: Vec<String>,
    pub algorithms: Option<Vec<String>>,
    pub proof_bounds: JsonObject,
    pub assertion_profile: AssertionProfile,
    pub stale_revocation_acknowledged: Option<bool>,
    pub replay_mode: ReplayMode,
    pub status: Status,
}

/// The mutable columns of a source, all replaced by the crate-private
/// `update_trust_source`. `kind`,
/// `cluster_id` and `jwks_keyset_id` are immutable, so they are not here;
/// the kind-specific fields that are must still match the stored kind.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustSourceChanges {
    pub name: String,
    pub exact_issuer: String,
    pub discovery_url: Option<String>,
    pub token_review_endpoint: Option<String>,
    pub ca_bundle_ref: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub reviewer_credential_ref: Option<String>,
    pub review_timeout_ms: Option<i32>,
    pub audiences: Vec<String>,
    pub algorithms: Option<Vec<String>>,
    pub proof_bounds: JsonObject,
    pub assertion_profile: AssertionProfile,
    pub stale_revocation_acknowledged: Option<bool>,
    pub replay_mode: ReplayMode,
    pub status: Status,
}

/// A principal binding: verified evidence of one source mapped to one
/// workload principal (design section 5.3; ADR-016; ADR-022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalBinding {
    pub id: String,
    pub tenant_id: String,
    /// Unique within the tenant.
    pub name: String,
    /// A same-tenant source; immutable.
    pub trust_source_id: String,
    pub profile: BindingProfile,
    /// ANDed exact-string predicates, claim name to value; nonempty.
    pub claim_match_policy: BTreeMap<String, String>,
    /// A same-tenant workload principal; immutable.
    pub workload_principal_id: String,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for PrincipalBinding {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            trust_source_id: row.try_get("trust_source_id")?,
            profile: text(row, "profile")?,
            claim_match_policy: json(row, "claim_match_policy")?,
            workload_principal_id: row.try_get("workload_principal_id")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the registry-private `create_principal_binding` (tests
/// reach it through the `test-support` feature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrincipalBinding {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub trust_source_id: String,
    pub profile: BindingProfile,
    pub claim_match_policy: BTreeMap<String, String>,
    pub workload_principal_id: String,
    pub status: Status,
}

/// The mutable columns of a binding, all replaced by the registry-private
/// `update_principal_binding` (tests only, through the `test-support`
/// feature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalBindingChanges {
    pub name: String,
    pub profile: BindingProfile,
    pub claim_match_policy: BTreeMap<String, String>,
    pub status: Status,
}

/// A service identity; its ID is that of a same-tenant service principal
/// (tasks section 3 "Ownership").
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceIdentity {
    pub id: String,
    pub tenant_id: String,
    /// Unique within the tenant.
    pub name: String,
    pub max_scopes: Vec<String>,
    pub max_resource_constraints: JsonObject,
    /// The resource servers of its rows in
    /// `service_identity_resource_server`, sorted byte-wise. Each has an
    /// assignment to the identity's tenant, whatever its status.
    pub resource_server_ids: Vec<String>,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for ServiceIdentity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            max_scopes: json(row, "max_scopes")?,
            max_resource_constraints: json(row, "max_resource_constraints")?,
            resource_server_ids: row.try_get("resource_server_ids")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the registry-private `create_service_identity` (tests
/// reach it through the `test-support` feature), with the identity's
/// initial audiences.
#[derive(Debug, Clone, PartialEq)]
pub struct NewServiceIdentity {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub max_scopes: Vec<String>,
    pub max_resource_constraints: JsonObject,
    pub resource_server_ids: Vec<String>,
    pub status: Status,
}

/// The mutable columns of a service identity, all replaced by the
/// registry-private `update_service_identity` (tests only, through the
/// `test-support` feature). Its audiences are unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceIdentityChanges {
    pub name: String,
    pub max_scopes: Vec<String>,
    pub max_resource_constraints: JsonObject,
    pub status: Status,
}

/// A service grant (design sections 5.6 and 5.7; ADR-006; ADR-022 items 10
/// to 13).
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceGrant {
    pub id: String,
    pub tenant_id: String,
    /// Unique within the tenant.
    pub name: String,
    /// A same-tenant workload principal; immutable.
    pub actor_principal_id: String,
    /// A same-tenant service identity exactly for delegation and
    /// impersonation; immutable.
    pub target_service_id: Option<String>,
    /// Immutable.
    pub mode: GrantMode,
    pub scopes: Vec<String>,
    /// Nonempty and within `scopes` when set.
    pub default_scopes: Option<Vec<String>>,
    pub resource_constraints: JsonObject,
    /// Seconds, 1 to 300.
    pub max_ttl: i32,
    pub valid_until: Option<SystemTime>,
    pub status: Status,
    pub activation_state: ActivationState,
    /// The bindings of its rows in `service_grant_binding`, sorted
    /// byte-wise: same-tenant bindings of the grant's actor, never empty
    /// once committed.
    pub allowed_binding_ids: Vec<String>,
    /// The resource servers of its rows in `service_grant_resource_server`,
    /// sorted byte-wise.
    pub resource_server_ids: Vec<String>,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for ServiceGrant {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            actor_principal_id: row.try_get("actor_principal_id")?,
            target_service_id: row.try_get("target_service_id")?,
            mode: text(row, "mode")?,
            scopes: json(row, "scopes")?,
            default_scopes: optional_json(row, "default_scopes")?,
            resource_constraints: json(row, "resource_constraints")?,
            max_ttl: row.try_get("max_ttl")?,
            valid_until: timestamp(row, Origin::new("service_grant"), "valid_until")?,
            status: text(row, "status")?,
            activation_state: text(row, "activation_state")?,
            allowed_binding_ids: row.try_get("allowed_binding_ids")?,
            resource_server_ids: row.try_get("resource_server_ids")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of the registry-private `create_service_grant` (tests reach
/// it through the `test-support` feature), with the grant's initial
/// bindings and audiences. `allowed_binding_ids` must
/// not be empty by commit.
#[derive(Debug, Clone, PartialEq)]
pub struct NewServiceGrant {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub actor_principal_id: String,
    pub target_service_id: Option<String>,
    pub mode: GrantMode,
    pub scopes: Vec<String>,
    pub default_scopes: Option<Vec<String>>,
    pub resource_constraints: JsonObject,
    pub max_ttl: i32,
    pub valid_until: Option<SystemTime>,
    pub status: Status,
    pub activation_state: ActivationState,
    pub allowed_binding_ids: Vec<String>,
    pub resource_server_ids: Vec<String>,
}

/// The mutable columns of a grant, all replaced by the registry-private
/// `update_service_grant` (tests only, through the `test-support`
/// feature). The actor, target and mode are immutable; the bindings and
/// audiences are unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceGrantChanges {
    pub name: String,
    pub scopes: Vec<String>,
    pub default_scopes: Option<Vec<String>>,
    pub resource_constraints: JsonObject,
    pub max_ttl: i32,
    pub valid_until: Option<SystemTime>,
    pub status: Status,
    pub activation_state: ActivationState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_enums_round_trip_and_reject_other_values() {
        for status in [Status::Enabled, Status::Disabled] {
            assert_eq!(status.as_str().parse(), Ok(status));
            assert_eq!(status.to_string(), status.as_str());
        }
        for kind in [
            PrincipalKind::Human,
            PrincipalKind::Workload,
            PrincipalKind::Service,
        ] {
            assert_eq!(kind.as_str().parse(), Ok(kind));
        }
        for purpose in [
            EgressPurpose::OidcDiscovery,
            EgressPurpose::Jwks,
            EgressPurpose::TokenReview,
        ] {
            assert_eq!(purpose.as_str().parse(), Ok(purpose));
        }
        let err = "Enabled".parse::<Status>().unwrap_err();
        assert_eq!(err.to_string(), "not a Status value");
        assert!("".parse::<PrincipalKind>().is_err());
    }

    #[test]
    fn profiles_serialize_as_their_stored_values() {
        let profiles = [Profile::Wif, Profile::HumanCli, Profile::HumanSession];
        let json = serde_json::to_string(&profiles).unwrap();
        assert_eq!(json, r#"["wif","human_cli","human_session"]"#);
        for profile in profiles {
            assert_eq!(
                serde_json::to_value(profile).unwrap(),
                serde_json::Value::from(profile.as_str())
            );
            assert_eq!(profile.as_str().parse(), Ok(profile));
        }
        assert!(serde_json::from_str::<Profile>(r#""HumanCli""#).is_err());
    }

    #[test]
    fn trust_and_grant_enums_round_trip_their_stored_values() {
        for (kind, text) in [
            (TrustSourceKind::OidcDiscovery, "oidc_discovery"),
            (TrustSourceKind::UploadedJwks, "uploaded_jwks"),
            (
                TrustSourceKind::KubernetesTokenReview,
                "kubernetes_token_review",
            ),
        ] {
            assert_eq!((kind.as_str(), text.parse()), (text, Ok(kind)));
        }
        for (profile, text) in [
            (AssertionProfile::OnDemandJwt, "on_demand_jwt"),
            (AssertionProfile::ReusableJwt, "reusable_jwt"),
            (
                AssertionProfile::ProjectedServiceAccount,
                "projected_service_account",
            ),
        ] {
            assert_eq!((profile.as_str(), text.parse()), (text, Ok(profile)));
        }
        for (mode, text) in [
            (ReplayMode::Reusable, "reusable"),
            (ReplayMode::SingleUse, "single_use"),
        ] {
            assert_eq!((mode.as_str(), text.parse()), (text, Ok(mode)));
        }
        for (profile, text) in [
            (BindingProfile::GithubProduction, "github_production"),
            (
                BindingProfile::KubernetesProduction,
                "kubernetes_production",
            ),
            (BindingProfile::GenericProduction, "generic_production"),
        ] {
            assert_eq!((profile.as_str(), text.parse()), (text, Ok(profile)));
        }
        for (mode, text) in [
            (GrantMode::Direct, "direct"),
            (GrantMode::Delegation, "delegation"),
            (GrantMode::Impersonation, "impersonation"),
        ] {
            assert_eq!((mode.as_str(), text.parse()), (text, Ok(mode)));
        }
        for (state, text) in [
            (ActivationState::NotRequired, "not_required"),
            (ActivationState::RequiresReapproval, "requires_reapproval"),
        ] {
            assert_eq!((state.as_str(), text.parse()), (text, Ok(state)));
        }
        let err = "OidcDiscovery".parse::<TrustSourceKind>().unwrap_err();
        assert_eq!(err.to_string(), "not a TrustSourceKind value");
        assert!("".parse::<GrantMode>().is_err());
    }

    fn micros(time: SystemTime) -> i64 {
        let interval = since_epoch(time).unwrap();
        assert_eq!((interval.months, interval.days), (0, 0));
        interval.microseconds
    }

    #[test]
    fn times_since_the_epoch_truncate_toward_the_past() {
        assert_eq!(micros(UNIX_EPOCH), 0);
        assert_eq!(micros(UNIX_EPOCH + Duration::from_nanos(999)), 0);
        assert_eq!(micros(UNIX_EPOCH + Duration::from_nanos(1_500)), 1);
        assert_eq!(
            micros(UNIX_EPOCH + Duration::from_micros(1_767_323_045_678_901)),
            1_767_323_045_678_901
        );
        assert_eq!(micros(UNIX_EPOCH - Duration::from_nanos(1)), -1);
        assert_eq!(micros(UNIX_EPOCH - Duration::from_nanos(1_000)), -1);
        assert_eq!(micros(UNIX_EPOCH - Duration::from_nanos(1_001)), -2);
        assert_eq!(
            micros(UNIX_EPOCH - Duration::from_micros(86_400_000_000)),
            -86_400_000_000
        );
        assert_eq!(optional_since_epoch(None).unwrap(), None);
        assert_eq!(
            optional_since_epoch(Some(UNIX_EPOCH + Duration::from_micros(7)))
                .unwrap()
                .map(|interval| interval.microseconds),
            Some(7)
        );
    }

    #[test]
    fn a_floored_time_is_the_time_the_registry_stores() {
        let epoch = |nanos: i128| {
            let magnitude = Duration::from_nanos(u64::try_from(nanos.unsigned_abs()).unwrap());
            if nanos < 0 {
                UNIX_EPOCH - magnitude
            } else {
                UNIX_EPOCH + magnitude
            }
        };
        for (nanos, floored) in [
            (0, 0),
            (1, 0),
            (999, 0),
            (1_000, 1_000),
            (1_500, 1_000),
            (1_790_000_000_123_456_789, 1_790_000_000_123_456_000),
            (-1, -1_000),
            (-999, -1_000),
            (-1_000, -1_000),
            (-1_001, -2_000),
            (-86_400_000_000_500, -86_400_000_001_000),
        ] {
            let time = epoch(nanos);
            assert_eq!(floor_to_microsecond(time), epoch(floored), "{nanos}");
            // The write stores the floor: the same microseconds either way.
            assert_eq!(micros(floor_to_microsecond(time)), micros(time), "{nanos}");
            assert_eq!(i128::from(micros(time)) * 1_000, floored, "{nanos}");
        }
    }

    #[track_caller]
    fn assert_out_of_range(time: SystemTime) {
        let err = since_epoch(time).unwrap_err();
        assert!(matches!(err, sqlx::Error::Encode(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "error occurred while encoding a value: timestamp out of range"
        );
        assert!(matches!(
            super::super::RegistryError::from(err),
            super::super::RegistryError::Other(_)
        ));
    }

    #[test]
    fn times_before_the_earliest_timestamptz_are_encode_errors() {
        let earliest = Duration::from_micros(210_866_803_200_000_000);
        assert_eq!(micros(UNIX_EPOCH - earliest), EARLIEST_MICROSECONDS);
        assert_eq!(
            micros(UNIX_EPOCH - earliest + Duration::from_micros(1)),
            EARLIEST_MICROSECONDS + 1
        );
        // A partial microsecond before the floor truncates past it.
        assert_out_of_range(UNIX_EPOCH - earliest - Duration::from_nanos(1));
        assert_out_of_range(UNIX_EPOCH - earliest - Duration::from_micros(1));
        assert_out_of_range(UNIX_EPOCH - earliest * 2);
        let max = Duration::from_micros(u64::try_from(i64::MAX).unwrap());
        for beyond in [max, max + Duration::from_micros(1)] {
            if let Some(time) = UNIX_EPOCH.checked_sub(beyond) {
                assert_out_of_range(time);
            }
        }
    }

    #[test]
    fn times_after_the_latest_readable_microsecond_are_encode_errors() {
        let max = Duration::from_micros(u64::try_from(i64::MAX).unwrap());
        // SystemTime may not reach i64::MAX microseconds on every platform.
        if let Some(time) = UNIX_EPOCH.checked_add(max - Duration::from_micros(1)) {
            assert_eq!(micros(time), LATEST_MICROSECONDS);
            assert_eq!(
                micros(time + Duration::from_nanos(999)),
                LATEST_MICROSECONDS
            );
        }
        for beyond in [max, max + Duration::from_micros(1)] {
            if let Some(time) = UNIX_EPOCH.checked_add(beyond) {
                assert_out_of_range(time);
            }
        }
    }
}
