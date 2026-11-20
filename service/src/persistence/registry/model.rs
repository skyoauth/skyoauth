//! Typed rows of the registry tables and the inputs of their writes.

use std::{
    error::Error as StdError,
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{FromRow, Row, postgres::PgRow, types::Json};

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

/// Reads a text enumeration column.
fn text<T: FromStr<Err = UnknownValue>>(row: &PgRow, column: &str) -> Result<T, sqlx::Error> {
    row.try_get::<&str, _>(column)?
        .parse()
        .map_err(|source: UnknownValue| sqlx::Error::ColumnDecode {
            index: column.into(),
            source: source.into(),
        })
}

/// Reads a `jsonb` column.
fn json<T: DeserializeOwned>(row: &PgRow, column: &str) -> Result<T, sqlx::Error> {
    Ok(row.try_get::<Json<T>, _>(column)?.0)
}

/// Reads a timestamp that the query selected as microseconds since the Unix
/// epoch (`(extract(epoch FROM <column>) * 1000000)::bigint`), so the crate
/// needs no date-time dependency (inferred).
fn timestamp(row: &PgRow, column: &str) -> Result<Option<SystemTime>, sqlx::Error> {
    let Some(micros) = row.try_get::<Option<i64>, _>(column)? else {
        return Ok(None);
    };
    let offset = Duration::from_micros(micros.unsigned_abs());
    let time = if micros >= 0 {
        UNIX_EPOCH.checked_add(offset)
    } else {
        UNIX_EPOCH.checked_sub(offset)
    };
    time.map(Some).ok_or_else(|| sqlx::Error::ColumnDecode {
        index: column.into(),
        source: "timestamp out of range".into(),
    })
}

/// Reads a `NOT NULL` timestamp selected as [`timestamp`] expects.
fn required_timestamp(row: &PgRow, column: &str) -> Result<SystemTime, sqlx::Error> {
    timestamp(row, column)?.ok_or_else(|| sqlx::Error::ColumnDecode {
        index: column.into(),
        source: "unexpected NULL".into(),
    })
}

/// A tenant (identity-registry IR-030..IR-034). It has no revision column
/// yet (migrations README, "Not done in `0002`").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    /// Unique, immutable and server-generated (IR-034).
    pub secret_namespace: String,
    pub status: Status,
    pub created_at: SystemTime,
}

impl FromRow<'_, PgRow> for Tenant {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            secret_namespace: row.try_get("secret_namespace")?,
            status: text(row, "status")?,
            created_at: required_timestamp(row, "created_at_us")?,
        })
    }
}

/// The input of [`create_tenant`](super::create_tenant). `created_at` is
/// set by the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTenant {
    pub id: String,
    pub name: String,
    pub secret_namespace: String,
    pub status: Status,
}

/// A principal of a tenant (identity-registry section 5.1). It has no
/// revision column yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub tenant_id: String,
    pub kind: PrincipalKind,
    pub name: String,
    pub status: Status,
    pub created_at: SystemTime,
}

impl FromRow<'_, PgRow> for Principal {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            kind: text(row, "kind")?,
            name: row.try_get("name")?,
            status: text(row, "status")?,
            created_at: required_timestamp(row, "created_at_us")?,
        })
    }
}

/// The input of [`create_principal`](super::create_principal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrincipal {
    pub id: String,
    pub tenant_id: String,
    pub kind: PrincipalKind,
    pub name: String,
    pub status: Status,
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

/// The input of [`create_resource_server`](super::create_resource_server).
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

/// The mutable columns of a resource server, all replaced by
/// [`update_resource_server`](super::update_resource_server).
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

/// The input of
/// [`create_audience_tenant_assignment`](super::create_audience_tenant_assignment).
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

/// The mutable columns of an assignment, all replaced by
/// [`update_audience_tenant_assignment`](super::update_audience_tenant_assignment).
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

/// The input of
/// [`create_resource_server_checker`](super::create_resource_server_checker).
/// The checker starts with no tenants; see
/// [`add_resource_server_checker_tenant`](super::add_resource_server_checker_tenant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewResourceServerChecker {
    pub id: String,
    pub resource_server_id: String,
    pub public_mtls_identity: String,
    pub status: Status,
}

/// The mutable columns of a checker, all replaced by
/// [`update_resource_server_checker`](super::update_resource_server_checker).
/// The identity may be rotated (inferred in `0003`).
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

/// The input of [`create_resource_action`](super::create_resource_action).
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

/// The mutable columns of an action rule, all replaced by
/// [`update_resource_action`](super::update_resource_action).
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
            audit_sink_validated_at: timestamp(row, "audit_sink_validated_at_us")?,
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
}
