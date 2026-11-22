//! Typed errors of the registry functions and their SQLSTATE mapping.

use std::{borrow::Cow, error::Error as StdError, fmt};

use sqlx::error::DatabaseError;

/// `unique_violation`.
const UNIQUE_VIOLATION: &str = "23505";
/// `foreign_key_violation`.
const FOREIGN_KEY_VIOLATION: &str = "23503";
/// `check_violation`, also raised by a domain's `CHECK`.
const CHECK_VIOLATION: &str = "23514";
/// `not_null_violation`.
const NOT_NULL_VIOLATION: &str = "23502";
/// `serialization_failure`.
const SERIALIZATION_FAILURE: &str = "40001";
/// `deadlock_detected`.
const DEADLOCK_DETECTED: &str = "40P01";
/// The project SQLSTATE every guard trigger raises (migrations README,
/// "Conventions").
const GUARD: &str = "SK001";

/// Every constraint of the tables the registry writes (`tenant`,
/// `principal`, `audit_event` and `audit_chain_head`, the five `0003`
/// tables, the nine `0004` tables, `consumed_assertion` and the operator
/// tables `admin_identity`, `admin_credential` and `admin_role_binding` of
/// `0005`, `instance_security_policy` and `recovery_state`, which
/// bootstrap writes, and `administrative_operation`, which the recovery
/// challenges write) and of the three list domains, as migrations `0002` to `0005`, `0007`,
/// `0008` and `0009` name them, and the constraint names that the `0010`
/// assignment guards raise ([`ASSIGNMENT_ACTIVE`]), sorted byte-wise. A
/// unique, foreign key or check violation maps to a typed variant only for a
/// name listed here. The database test
/// `registry_constraint_names_match_the_catalog` keeps the list equal to the
/// catalog: the named constraints, and the triggers of the `0010` guard
/// function.
pub const KNOWN_CONSTRAINTS: &[&str] = &[
    // The three operator tables of `0005` (`operator.rs`).
    "admin_credential_admin_id_fkey",
    "admin_credential_admin_id_octet_length_check",
    "admin_credential_id_check",
    "admin_credential_id_octet_length_check",
    "admin_credential_pkey",
    "admin_credential_public_identity_check",
    "admin_credential_public_identity_key",
    "admin_credential_public_identity_octet_length_check",
    "admin_credential_revoked_at_range_check",
    "admin_credential_revoked_disabled_check",
    "admin_credential_status_check",
    "admin_credential_trust_anchor_ref_check",
    "admin_credential_trust_anchor_ref_no_space_check",
    "admin_credential_trust_anchor_ref_octet_length_check",
    "admin_identity_created_at_range_check",
    "admin_identity_id_check",
    "admin_identity_id_not_reserved_check",
    "admin_identity_id_octet_length_check",
    "admin_identity_pkey",
    "admin_identity_status_check",
    "admin_role_binding_admin_id_fkey",
    "admin_role_binding_admin_id_octet_length_check",
    "admin_role_binding_admin_id_role_tenant_id_key",
    "admin_role_binding_id_check",
    "admin_role_binding_id_octet_length_check",
    "admin_role_binding_pkey",
    "admin_role_binding_revision_check",
    "admin_role_binding_role_check",
    "admin_role_binding_scope_check",
    "admin_role_binding_status_check",
    "admin_role_binding_tenant_id_fkey",
    "admin_role_binding_tenant_id_octet_length_check",
    // The operations of `0005`, written by the recovery challenges
    // (`recovery.rs`).
    "administrative_operation_actor_id_check",
    "administrative_operation_actor_id_octet_length_check",
    "administrative_operation_approve_kind_check",
    "administrative_operation_approves_id_octet_length_check",
    "administrative_operation_approves_operation_id_fkey",
    "administrative_operation_approves_self_check",
    "administrative_operation_audit_id_fkey",
    "administrative_operation_audit_id_octet_length_check",
    "administrative_operation_challenge_expiry_check",
    "administrative_operation_challenge_hash_octet_length_check",
    "administrative_operation_consumed_at_range_check",
    "administrative_operation_consumed_before_expiry_check",
    "administrative_operation_expected_revision_check",
    "administrative_operation_expires_at_range_check",
    "administrative_operation_id_check",
    "administrative_operation_id_octet_length_check",
    "administrative_operation_immutable_plan_check",
    "administrative_operation_kind_check",
    "administrative_operation_kind_no_space_check",
    "administrative_operation_kind_octet_length_check",
    "administrative_operation_outcome_check",
    "administrative_operation_pkey",
    "administrative_operation_request_digest_octet_length_check",
    "administrative_operation_revision_check",
    "administrative_operation_revocation_check",
    "administrative_operation_revocation_id_octet_length_check",
    "administrative_operation_revocation_operation_id_fkey",
    "administrative_operation_revoked_at_range_check",
    "administrative_operation_revokes_self_check",
    "administrative_operation_tenant_id_fkey",
    "administrative_operation_tenant_id_octet_length_check",
    "audience_tenant_assignment_constraint_versions_check",
    "audience_tenant_assignment_id_check",
    "audience_tenant_assignment_id_octet_length_check",
    "audience_tenant_assignment_pkey",
    "audience_tenant_assignment_resource_server_id_fkey",
    "audience_tenant_assignment_revision_check",
    "audience_tenant_assignment_server_id_octet_length_check",
    "audience_tenant_assignment_status_check",
    "audience_tenant_assignment_tenant_id_fkey",
    "audience_tenant_assignment_tenant_id_octet_length_check",
    "audience_tenant_assignment_tenant_id_resource_server_id_key",
    "audit_chain_head_check",
    "audit_chain_head_head_hash_check",
    "audit_chain_head_pkey",
    "audit_chain_head_sequence_check",
    "audit_chain_head_singleton_check",
    "audit_event_action_check",
    "audit_event_actor_check",
    "audit_event_check",
    "audit_event_id_check",
    "audit_event_id_octet_length_check",
    "audit_event_new_revision_check",
    "audit_event_object_id_check",
    "audit_event_outcome_check",
    "audit_event_pkey",
    "audit_event_prev_hash_check",
    "audit_event_previous_revision_check",
    "audit_event_sequence_check",
    "audit_event_sequence_key",
    "audit_event_tenant_id_fkey",
    "audit_event_tenant_id_octet_length_check",
    "audit_event_timestamp_range_check",
    "consumed_assertion_consumed_at_range_check",
    "consumed_assertion_digest_key_version_check",
    "consumed_assertion_digest_key_version_octet_length_check",
    "consumed_assertion_pkey",
    "consumed_assertion_replay_key_digest_octet_length_check",
    "consumed_assertion_retain_until_range_check",
    "consumed_assertion_retention_check",
    "consumed_assertion_tenant_id_octet_length_check",
    "consumed_assertion_trust_source_id_fkey",
    "consumed_assertion_trust_source_id_octet_length_check",
    // The policy row and the recovery state, written by bootstrap
    // (`bootstrap.rs`). Their single-row unique indexes are not
    // constraints; bootstrap maps a `23505` on them itself.
    "instance_security_policy_audit_sink_config_digest_check",
    "instance_security_policy_audit_sink_validated_at_range_check",
    "instance_security_policy_check",
    "instance_security_policy_instance_id_check",
    "instance_security_policy_instance_id_octet_length_check",
    "instance_security_policy_pkey",
    "instance_security_policy_revision_check",
    "principal_binding_claim_match_policy_check",
    "principal_binding_generic_production_predicates_check",
    "principal_binding_github_production_predicates_check",
    "principal_binding_id_check",
    "principal_binding_id_octet_length_check",
    "principal_binding_kubernetes_production_predicates_check",
    "principal_binding_name_check",
    "principal_binding_name_no_space_check",
    "principal_binding_name_octet_length_check",
    "principal_binding_pkey",
    "principal_binding_profile_check",
    "principal_binding_revision_check",
    "principal_binding_status_check",
    "principal_binding_tenant_id_fkey",
    "principal_binding_tenant_id_id_key",
    "principal_binding_tenant_id_id_workload_principal_id_key",
    "principal_binding_tenant_id_name_key",
    "principal_binding_tenant_id_octet_length_check",
    "principal_binding_trust_source_id_fkey",
    "principal_binding_trust_source_id_octet_length_check",
    "principal_binding_workload_principal_id_fkey",
    "principal_binding_workload_principal_id_octet_length_check",
    "principal_binding_workload_principal_kind_check",
    "principal_created_at_range_check",
    "principal_id_check",
    "principal_id_octet_length_check",
    "principal_kind_check",
    "principal_name_check",
    "principal_pkey",
    "principal_revision_check",
    "principal_status_check",
    "principal_tenant_id_fkey",
    "principal_tenant_id_id_key",
    "principal_tenant_id_id_kind_key",
    "principal_tenant_id_octet_length_check",
    "recovery_state_instance_id_check",
    "recovery_state_instance_id_fkey",
    "recovery_state_instance_id_octet_length_check",
    "recovery_state_pkey",
    "recovery_state_recovery_key_epoch_check",
    "recovery_state_recovery_public_key_octet_length_check",
    "recovery_state_revision_check",
    "resource_action_action_name_check",
    "resource_action_action_name_no_space_check",
    "resource_action_action_name_octet_length_check",
    "resource_action_id_check",
    "resource_action_id_octet_length_check",
    "resource_action_pkey",
    "resource_action_resource_server_id_action_name_key",
    "resource_action_resource_server_id_fkey",
    "resource_action_resource_server_id_octet_length_check",
    "resource_action_revision_check",
    "resource_action_status_check",
    "resource_server_audience_check",
    "resource_server_audience_key",
    "resource_server_audience_no_space_check",
    "resource_server_audience_octet_length_check",
    "resource_server_checker_id_check",
    "resource_server_checker_id_octet_length_check",
    "resource_server_checker_id_resource_server_id_key",
    "resource_server_checker_pkey",
    "resource_server_checker_public_mtls_identity_check",
    "resource_server_checker_public_mtls_identity_key",
    "resource_server_checker_public_mtls_identity_octet_length_check",
    "resource_server_checker_resource_server_id_fkey",
    "resource_server_checker_resource_server_id_octet_length_check",
    "resource_server_checker_revision_check",
    "resource_server_checker_status_check",
    "resource_server_checker_tenant_assignment_fkey",
    "resource_server_checker_tenant_checker_fkey",
    "resource_server_checker_tenant_checker_id_octet_length_check",
    "resource_server_checker_tenant_pkey",
    "resource_server_checker_tenant_server_id_octet_length_check",
    "resource_server_checker_tenant_tenant_id_octet_length_check",
    "resource_server_constraint_versions_check",
    "resource_server_id_check",
    "resource_server_id_octet_length_check",
    "resource_server_name_check",
    "resource_server_pkey",
    "resource_server_revision_check",
    "resource_server_status_check",
    "service_grant_activation_mode_check",
    "service_grant_activation_state_check",
    "service_grant_actor_principal_id_fkey",
    "service_grant_actor_principal_id_octet_length_check",
    "service_grant_actor_principal_kind_check",
    "service_grant_binding_actor_principal_id_octet_length_check",
    "service_grant_binding_binding_id_fkey",
    "service_grant_binding_binding_id_octet_length_check",
    "service_grant_binding_grant_id_fkey",
    "service_grant_binding_grant_id_octet_length_check",
    "service_grant_binding_pkey",
    "service_grant_binding_tenant_id_octet_length_check",
    "service_grant_default_scopes_check",
    "service_grant_id_check",
    "service_grant_id_octet_length_check",
    "service_grant_impersonation_disabled_check",
    "service_grant_max_ttl_check",
    "service_grant_mode_check",
    "service_grant_name_check",
    "service_grant_name_no_space_check",
    "service_grant_name_octet_length_check",
    "service_grant_pkey",
    "service_grant_resource_constraints_check",
    // Not a catalog constraint: the name the `0010` guard trigger of
    // the same name raises with its `23514` ([`ASSIGNMENT_ACTIVE`]).
    "service_grant_resource_server_assignment_active",
    "service_grant_resource_server_assignment_fkey",
    "service_grant_resource_server_grant_id_fkey",
    "service_grant_resource_server_grant_id_octet_length_check",
    "service_grant_resource_server_pkey",
    "service_grant_resource_server_server_id_octet_length_check",
    "service_grant_resource_server_tenant_id_octet_length_check",
    "service_grant_revision_check",
    "service_grant_status_check",
    "service_grant_target_mode_check",
    "service_grant_target_service_id_fkey",
    "service_grant_target_service_id_octet_length_check",
    "service_grant_tenant_id_fkey",
    "service_grant_tenant_id_id_actor_principal_id_key",
    "service_grant_tenant_id_id_key",
    "service_grant_tenant_id_name_key",
    "service_grant_tenant_id_octet_length_check",
    "service_grant_valid_until_range_check",
    "service_identity_id_check",
    "service_identity_id_fkey",
    "service_identity_id_octet_length_check",
    "service_identity_max_resource_constraints_check",
    "service_identity_name_check",
    "service_identity_name_no_space_check",
    "service_identity_name_octet_length_check",
    "service_identity_pkey",
    "service_identity_principal_kind_check",
    // As above, the `0010` guard of the identity's audience rows.
    "service_identity_resource_server_assignment_active",
    "service_identity_resource_server_assignment_fkey",
    "service_identity_resource_server_pkey",
    "service_identity_resource_server_server_id_octet_length_check",
    "service_identity_resource_server_service_id_fkey",
    "service_identity_resource_server_service_id_octet_length_check",
    "service_identity_resource_server_tenant_id_octet_length_check",
    "service_identity_revision_check",
    "service_identity_status_check",
    "service_identity_tenant_id_fkey",
    "service_identity_tenant_id_id_key",
    "service_identity_tenant_id_name_key",
    "service_identity_tenant_id_octet_length_check",
    "skyoauth_profile_list_check",
    "skyoauth_scope_list_check",
    "skyoauth_string_list_check",
    "tenant_created_at_range_check",
    "tenant_id_check",
    "tenant_id_octet_length_check",
    "tenant_name_check",
    "tenant_pkey",
    "tenant_revision_check",
    "tenant_secret_namespace_check",
    "tenant_secret_namespace_key",
    "tenant_secret_namespace_octet_length_check",
    "tenant_status_check",
    "trust_keyset_id_check",
    "trust_keyset_id_octet_length_check",
    "trust_keyset_name_check",
    "trust_keyset_name_no_space_check",
    "trust_keyset_name_octet_length_check",
    "trust_keyset_pkey",
    "trust_keyset_revision_check",
    "trust_keyset_status_check",
    "trust_keyset_tenant_id_fkey",
    "trust_keyset_tenant_id_id_key",
    "trust_keyset_tenant_id_name_key",
    "trust_keyset_tenant_id_octet_length_check",
    "trust_keyset_version_effective_at_range_check",
    "trust_keyset_version_expires_at_range_check",
    "trust_keyset_version_fingerprint_check",
    "trust_keyset_version_fingerprint_no_space_check",
    "trust_keyset_version_fingerprint_octet_length_check",
    "trust_keyset_version_id_check",
    "trust_keyset_version_id_octet_length_check",
    "trust_keyset_version_keyset_id_fkey",
    "trust_keyset_version_keyset_id_octet_length_check",
    "trust_keyset_version_pkey",
    "trust_keyset_version_provenance_check",
    "trust_keyset_version_public_jwks_check",
    "trust_keyset_version_revision_check",
    "trust_keyset_version_status_check",
    "trust_keyset_version_tenant_id_fkey",
    "trust_keyset_version_tenant_id_id_key",
    "trust_keyset_version_tenant_id_octet_length_check",
    "trust_keyset_version_validity_check",
    "trust_source_algorithms_check",
    "trust_source_algorithms_kind_check",
    "trust_source_assertion_profile_check",
    "trust_source_audiences_check",
    "trust_source_ca_bundle_ref_check",
    "trust_source_ca_bundle_ref_no_space_check",
    "trust_source_ca_bundle_ref_octet_length_check",
    "trust_source_ca_fingerprint_check",
    "trust_source_ca_fingerprint_no_space_check",
    "trust_source_ca_fingerprint_octet_length_check",
    "trust_source_cluster_id_check",
    "trust_source_cluster_id_key",
    "trust_source_cluster_id_octet_length_check",
    "trust_source_discovery_url_check",
    "trust_source_discovery_url_kind_check",
    "trust_source_discovery_url_no_space_check",
    "trust_source_discovery_url_octet_length_check",
    "trust_source_exact_issuer_check",
    "trust_source_exact_issuer_no_space_check",
    "trust_source_exact_issuer_octet_length_check",
    "trust_source_id_check",
    "trust_source_id_octet_length_check",
    "trust_source_jwks_keyset_id_fkey",
    "trust_source_jwks_keyset_id_kind_check",
    "trust_source_jwks_keyset_id_octet_length_check",
    "trust_source_kind_check",
    "trust_source_name_check",
    "trust_source_name_no_space_check",
    "trust_source_name_octet_length_check",
    "trust_source_pkey",
    "trust_source_proof_bounds_check",
    "trust_source_replay_mode_check",
    "trust_source_review_timeout_ms_check",
    "trust_source_reviewer_credential_ref_check",
    "trust_source_reviewer_credential_ref_no_space_check",
    "trust_source_reviewer_credential_ref_octet_length_check",
    "trust_source_revision_check",
    "trust_source_single_use_replay_check",
    "trust_source_stale_revocation_acknowledged_check",
    "trust_source_stale_revocation_kind_check",
    "trust_source_status_check",
    "trust_source_tenant_id_fkey",
    "trust_source_tenant_id_id_key",
    "trust_source_tenant_id_name_key",
    "trust_source_tenant_id_octet_length_check",
    "trust_source_token_review_endpoint_check",
    "trust_source_token_review_endpoint_no_space_check",
    "trust_source_token_review_endpoint_octet_length_check",
    "trust_source_token_review_fields_kind_check",
    "trust_source_token_review_profile_check",
];

/// The constraint names that the two `0010` guard triggers raise with a
/// `check_violation` (`23514`) when the audience tenant assignment of a new
/// audience row of a service identity or a grant is not enabled (IR-080;
/// provisional lead pick, 2026-11-22). Each is the name of the trigger that
/// raises it; both are in [`KNOWN_CONSTRAINTS`]. They map to
/// [`InvariantKind::AssignmentActive`], not to [`InvariantKind::Check`].
pub const ASSIGNMENT_ACTIVE: [&str; 2] = [
    "service_grant_resource_server_assignment_active",
    "service_identity_resource_server_assignment_active",
];

/// The error of a registry function.
///
/// The variants carry only constraint names from [`KNOWN_CONSTRAINTS`],
/// table and column names, and the claim names of
/// [`required_claims`](super::required_claims), never a value from the
/// request or the row, and
/// `Display` and `Debug` print nothing else. The one exception is the row ID
/// of [`RegistryError::UnreadableTimestamp`], which `Display` and `Debug`
/// leave out (inferred). The database's own message for a retryable or an
/// unmapped error is reachable only through [`std::error::Error::source`]
/// of [`RegistryError::Retry`] and [`RegistryError::Other`]: that source is
/// the raw [`sqlx::Error`], whose message and detail may quote request or
/// row values, so logging must not walk the source chain.
///
/// The enum is `#[non_exhaustive]`: a later task may add a variant, so a
/// `match` outside this crate needs a wildcard arm.
#[non_exhaustive]
pub enum RegistryError {
    /// No row has the given ID (in the given tenant, for a tenant-owned
    /// table), or a list set does not contain the item to remove (a
    /// checker's tenant, or a service identity's audience, a grant's binding
    /// or a grant's audience).
    NotFound,
    /// The row exists, but its revision is not the expected one: another
    /// write came first. Nothing was changed.
    StaleRevision,
    /// A unique key (`23505`) already holds the value: the primary key or
    /// another unique constraint, named by `constraint`.
    AlreadyExists {
        /// The violated constraint, for example `tenant_secret_namespace_key`.
        constraint: &'static str,
    },
    /// A foreign key (`23503`), check (`23514`) or not-null (`23502`)
    /// constraint rejected the write.
    Invariant {
        /// Which kind of constraint.
        kind: InvariantKind,
        /// The violated constraint, so callers can tell a length bound
        /// (`…_octet_length_check`) from a character rule (`…_no_space_check`)
        /// or a list domain (`skyoauth_scope_list_check`). `None` for a
        /// not-null violation, which PostgreSQL does not name.
        constraint: Option<&'static str>,
    },
    /// A guard trigger rejected the write (`SK001`), for example a change to
    /// an immutable column or a revision that does not advance by one. The
    /// grant binding-set check (`service_grant_has_binding` and
    /// `service_grant_binding_keeps_one`) is a deferred constraint trigger,
    /// so inside a transaction it fails at the caller's commit, not at the
    /// statement: map the commit's error with `RegistryError::from`.
    Guard,
    /// A stored `timestamptz` is outside the range the registry reads
    /// (`infinity`, `-infinity`, or a finite time after `i64::MAX - 1`
    /// microseconds from the Unix epoch), so the row cannot be returned. The
    /// `0007` range checks keep such a time out; a row written while a check
    /// was dropped (or left in place by a `NOT VALID` re-add), or read from
    /// a schema not yet migrated to `0007`, can still hold one. It is not an
    /// [`Self::Invariant`]: no write was rejected (lead ruling, 2026-11-21).
    UnreadableTimestamp {
        /// The table, for example `tenant`.
        table: &'static str,
        /// The column, for example `created_at`.
        column: &'static str,
        /// The ID of the row (`instance_id` for the instance security
        /// policy), so an operator can repair it (migrations README, "What
        /// 0007 adds"). `Display` and `Debug` leave it out (inferred: the
        /// no-values convention covers row values, and an ID is one).
        id: String,
    },
    /// The database aborted the transaction with `40001`
    /// (`serialization_failure`) or `40P01` (`deadlock_detected`): retry
    /// the whole transaction. A `40001` is never [`Self::StaleRevision`]:
    /// it means the transaction conflicts with a concurrent one, not that
    /// the caller must read the row again. As for [`Self::Other`], the
    /// wrapped [`sqlx::Error`] is reachable only as the
    /// [`source`](StdError::source).
    Retry(sqlx::Error),
    /// Any other error: a connection or decode failure, an unexpected
    /// SQLSTATE, or a constraint missing from [`KNOWN_CONSTRAINTS`].
    Other(sqlx::Error),
    /// The ID of a new operator identity is reserved for an actor that is
    /// not an operator identity (`deployment_operator`, or one beginning
    /// with `recovery_key:`; see
    /// [`is_reserved_actor_id`](super::is_reserved_actor_id)). Returned
    /// before any statement runs; nothing was written.
    ReservedActorId,
    /// The `claim_match_policy` of a binding lacks a predicate its profile
    /// requires, or holds it with an empty value (ADR-016 items 2 to 4;
    /// [`validate_claim_match_policy`](super::validate_claim_match_policy)).
    /// Returned before any statement runs; nothing was written. The first
    /// unmet predicate, in the order of
    /// [`required_claims`](super::required_claims), is the one named.
    RequiredPredicate {
        /// The claim name of the predicate, from
        /// [`required_claims`](super::required_claims), for example
        /// `repository_owner_id`; never a value of the policy.
        claim: &'static str,
        /// Whether the key is absent or its value is empty.
        problem: PredicateProblem,
    },
}

/// Why a required predicate is unmet, in [`RegistryError::RequiredPredicate`].
/// `Display` prints `missing` or `empty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateProblem {
    /// The policy has no key with the claim name (byte-wise).
    Missing,
    /// The policy has the key with an empty string. A whitespace-only value
    /// is not empty.
    Empty,
}

impl fmt::Display for PredicateProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
        })
    }
}

/// The kind of constraint behind [`RegistryError::Invariant`].
///
/// The enum is `#[non_exhaustive]` (since `0010` added
/// [`Self::AssignmentActive`]): a later guard may add a kind, so a `match`
/// outside this crate needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvariantKind {
    /// `23503`: a referenced row does not exist, for example a checker
    /// tenant without an assignment of the checker's resource server.
    ForeignKey,
    /// `23514`: a table or domain `CHECK`.
    Check,
    /// `23502`: a required column is `NULL`.
    NotNull,
    /// `23514` from a `0010` guard trigger ([`ASSIGNMENT_ACTIVE`]): the
    /// audience tenant assignment that a new audience row of a service
    /// identity or a grant references exists but is not enabled (IR-080;
    /// provisional lead pick, 2026-11-22). A missing assignment is
    /// [`Self::ForeignKey`] instead.
    AssignmentActive,
}

impl InvariantKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ForeignKey => "foreign key",
            Self::Check => "check",
            Self::NotNull => "not-null",
            Self::AssignmentActive => "active-assignment",
        }
    }
}

/// The decode error a row's `FromRow` returns for a time outside the readable
/// range, carried to [`RegistryError::from`] as the source of a
/// [`sqlx::Error::ColumnDecode`], which turns it into
/// [`RegistryError::UnreadableTimestamp`].
pub(super) struct UnreadableTimestamp {
    pub(super) table: &'static str,
    pub(super) column: &'static str,
    pub(super) id: String,
}

/// Like `Display`, `Debug` leaves out the row ID, as
/// [`RegistryError::UnreadableTimestamp`] does: the `Debug` of a
/// [`sqlx::Error::ColumnDecode`] that carries this error prints it.
impl fmt::Debug for UnreadableTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnreadableTimestamp")
            .field("table", &self.table)
            .field("column", &self.column)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for UnreadableTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{} is outside the readable timestamp range",
            self.table, self.column
        )
    }
}

impl StdError for UnreadableTimestamp {}

/// The constraint name as listed in [`KNOWN_CONSTRAINTS`].
fn known_constraint(name: &str) -> Option<&'static str> {
    KNOWN_CONSTRAINTS
        .binary_search(&name)
        .ok()
        .map(|index| KNOWN_CONSTRAINTS[index])
}

/// Whether a database error aborted the transaction so that only a retry
/// of the whole transaction can succeed: [`RegistryError::Retry`].
fn is_retry(error: &dyn DatabaseError) -> bool {
    error
        .code()
        .is_some_and(|code| matches!(code.as_ref(), SERIALIZATION_FAILURE | DEADLOCK_DETECTED))
}

/// The typed error for a database error that is not [`is_retry`], or `None`
/// when it maps to [`RegistryError::Other`].
fn classify(error: &dyn DatabaseError) -> Option<RegistryError> {
    let named = || error.constraint().and_then(known_constraint);
    Some(match error.code()?.as_ref() {
        UNIQUE_VIOLATION => RegistryError::AlreadyExists {
            constraint: named()?,
        },
        FOREIGN_KEY_VIOLATION => RegistryError::Invariant {
            kind: InvariantKind::ForeignKey,
            constraint: Some(named()?),
        },
        CHECK_VIOLATION => {
            let constraint = named()?;
            RegistryError::Invariant {
                kind: if ASSIGNMENT_ACTIVE.contains(&constraint) {
                    InvariantKind::AssignmentActive
                } else {
                    InvariantKind::Check
                },
                constraint: Some(constraint),
            }
        }
        NOT_NULL_VIOLATION => RegistryError::Invariant {
            kind: InvariantKind::NotNull,
            constraint: None,
        },
        GUARD => RegistryError::Guard,
        _ => return None,
    })
}

impl From<sqlx::Error> for RegistryError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::ColumnDecode { source, .. } = &error
            && let Some(unreadable) = source.downcast_ref::<UnreadableTimestamp>()
        {
            return Self::UnreadableTimestamp {
                table: unreadable.table,
                column: unreadable.column,
                id: unreadable.id.clone(),
            };
        }
        if error.as_database_error().is_some_and(is_retry) {
            return Self::Retry(error);
        }
        match error.as_database_error().and_then(classify) {
            Some(mapped) => mapped,
            None => Self::Other(error),
        }
    }
}

impl RegistryError {
    /// The SQLSTATE of the database error wrapped by
    /// [`RegistryError::Retry`] or [`RegistryError::Other`].
    fn sqlstate(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Retry(error) | Self::Other(error) => error.as_database_error()?.code(),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "registry row not found"),
            Self::StaleRevision => write!(
                f,
                "registry row is not at the expected revision; read it again"
            ),
            Self::AlreadyExists { constraint } => {
                write!(f, "registry row already exists (unique {constraint})")
            }
            Self::Invariant {
                kind,
                constraint: Some(constraint),
            } => write!(
                f,
                "registry write violates {} constraint {constraint}",
                kind.as_str()
            ),
            Self::Invariant {
                kind,
                constraint: None,
            } => write!(f, "registry write violates a {} constraint", kind.as_str()),
            Self::Guard => write!(f, "registry write rejected by a schema guard (SK001)"),
            Self::UnreadableTimestamp { table, column, .. } => write!(
                f,
                "registry row has a {table}.{column} outside the readable timestamp range"
            ),
            Self::Retry(_) => match self.sqlstate() {
                Some(code) => write!(
                    f,
                    "registry transaction aborted (SQLSTATE {code}); retry the whole transaction"
                ),
                None => write!(
                    f,
                    "registry transaction aborted; retry the whole transaction"
                ),
            },
            Self::Other(_) => match self.sqlstate() {
                Some(code) => write!(f, "registry database error (SQLSTATE {code})"),
                None => write!(f, "registry database error"),
            },
            Self::ReservedActorId => write!(
                f,
                "registry ID is reserved for an actor that is not an operator identity"
            ),
            Self::RequiredPredicate { claim, problem } => write!(
                f,
                "registry binding's required predicate {claim} is {problem}"
            ),
        }
    }
}

/// Like `Display`, `Debug` leaves out the wrapped [`sqlx::Error`] of
/// `Retry` and `Other`, whose `Debug` includes the server's detail line
/// (the key values of a violation).
impl fmt::Debug for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("NotFound"),
            Self::StaleRevision => f.write_str("StaleRevision"),
            Self::AlreadyExists { constraint } => f
                .debug_struct("AlreadyExists")
                .field("constraint", constraint)
                .finish(),
            Self::Invariant { kind, constraint } => f
                .debug_struct("Invariant")
                .field("kind", kind)
                .field("constraint", constraint)
                .finish(),
            Self::Guard => f.write_str("Guard"),
            Self::UnreadableTimestamp { table, column, .. } => f
                .debug_struct("UnreadableTimestamp")
                .field("table", table)
                .field("column", column)
                .finish_non_exhaustive(),
            Self::Retry(_) => f
                .debug_struct("Retry")
                .field("sqlstate", &self.sqlstate())
                .finish_non_exhaustive(),
            Self::Other(_) => f
                .debug_struct("Other")
                .field("sqlstate", &self.sqlstate())
                .finish_non_exhaustive(),
            Self::ReservedActorId => f.write_str("ReservedActorId"),
            Self::RequiredPredicate { claim, problem } => f
                .debug_struct("RequiredPredicate")
                .field("claim", claim)
                .field("problem", problem)
                .finish(),
        }
    }
}

impl StdError for RegistryError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Retry(error) | Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::error::ErrorKind;

    /// A database error with a chosen SQLSTATE and constraint, and a message
    /// and detail that stand for user-supplied values.
    #[derive(Debug)]
    struct FakeDbError {
        code: Option<&'static str>,
        constraint: Option<&'static str>,
    }

    const SECRET: &str = "user-value-ns_secret";

    impl fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Key (secret_namespace)=({SECRET}) already exists")
        }
    }

    impl StdError for FakeDbError {}

    impl DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            SECRET
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.map(Cow::Borrowed)
        }
        fn constraint(&self) -> Option<&str> {
            self.constraint
        }
        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    fn map(code: Option<&'static str>, constraint: Option<&'static str>) -> RegistryError {
        RegistryError::from(sqlx::Error::database(FakeDbError { code, constraint }))
    }

    fn assert_redacted(error: &RegistryError) {
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("user-value"), "{text}");
        }
    }

    #[test]
    fn known_constraints_are_sorted_and_unique() {
        assert!(KNOWN_CONSTRAINTS.windows(2).all(|w| w[0] < w[1]));
        for name in KNOWN_CONSTRAINTS {
            assert_eq!(known_constraint(name), Some(*name));
        }
        assert_eq!(known_constraint("tenant_pkey_x"), None);
        assert_eq!(known_constraint(""), None);
    }

    #[test]
    fn unique_violation_maps_to_already_exists_with_its_constraint() {
        let error = map(Some("23505"), Some("tenant_secret_namespace_key"));
        assert!(matches!(
            error,
            RegistryError::AlreadyExists {
                constraint: "tenant_secret_namespace_key"
            }
        ));
        assert_eq!(
            error.to_string(),
            "registry row already exists (unique tenant_secret_namespace_key)"
        );
        assert_redacted(&error);
    }

    #[test]
    fn foreign_key_violation_maps_to_invariant_with_its_constraint() {
        let error = map(
            Some("23503"),
            Some("resource_server_checker_tenant_assignment_fkey"),
        );
        assert!(matches!(
            error,
            RegistryError::Invariant {
                kind: InvariantKind::ForeignKey,
                constraint: Some("resource_server_checker_tenant_assignment_fkey")
            }
        ));
        assert_eq!(
            error.to_string(),
            "registry write violates foreign key constraint \
             resource_server_checker_tenant_assignment_fkey"
        );
        assert_redacted(&error);
    }

    #[test]
    fn check_violation_keeps_the_name_that_tells_bound_from_character_rule() {
        for name in [
            "resource_server_audience_octet_length_check",
            "resource_server_audience_no_space_check",
            "skyoauth_scope_list_check",
        ] {
            let error = map(Some("23514"), Some(name));
            match &error {
                RegistryError::Invariant {
                    kind: InvariantKind::Check,
                    constraint: Some(constraint),
                } => assert_eq!(*constraint, name),
                other => panic!("{other:?}"),
            }
            assert_redacted(&error);
        }
    }

    #[test]
    fn trust_binding_and_grant_constraints_map_by_name() {
        for name in [
            "trust_source_cluster_id_key",
            "service_grant_binding_pkey",
            "principal_binding_tenant_id_name_key",
        ] {
            let error = map(Some("23505"), Some(name));
            assert!(
                matches!(error, RegistryError::AlreadyExists { constraint } if constraint == name),
                "{error:?}"
            );
            assert_redacted(&error);
        }
        for (code, kind, name) in [
            (
                "23503",
                InvariantKind::ForeignKey,
                "service_grant_binding_binding_id_fkey",
            ),
            (
                "23503",
                InvariantKind::ForeignKey,
                "service_identity_resource_server_assignment_fkey",
            ),
            (
                "23514",
                InvariantKind::Check,
                "trust_source_token_review_fields_kind_check",
            ),
            (
                "23514",
                InvariantKind::Check,
                "service_grant_resource_server_server_id_octet_length_check",
            ),
            (
                "23514",
                InvariantKind::Check,
                "trust_keyset_version_validity_check",
            ),
        ] {
            let error = map(Some(code), Some(name));
            match &error {
                RegistryError::Invariant {
                    kind: actual,
                    constraint: Some(constraint),
                } => assert_eq!((*actual, *constraint), (kind, name)),
                other => panic!("{other:?}"),
            }
            assert_redacted(&error);
        }
        // The deferred binding-set check at commit is a guard like any other.
        assert!(matches!(map(Some("SK001"), None), RegistryError::Guard));
    }

    /// The `0010` guards' `23514` names their trigger and maps to
    /// `AssignmentActive`, never `Check`; a `23503` of the same table's
    /// assignment key stays `ForeignKey`, and a `40001` or `40P01` naming it
    /// is still `Retry`.
    #[test]
    fn an_inactive_assignment_maps_to_its_own_invariant_kind() {
        assert!(ASSIGNMENT_ACTIVE.windows(2).all(|w| w[0] < w[1]));
        for name in ASSIGNMENT_ACTIVE {
            assert_eq!(known_constraint(name), Some(name));
            let error = map(Some("23514"), Some(name));
            match &error {
                RegistryError::Invariant {
                    kind: InvariantKind::AssignmentActive,
                    constraint: Some(constraint),
                } => assert_eq!(*constraint, name),
                other => panic!("{other:?}"),
            }
            assert_eq!(
                error.to_string(),
                format!("registry write violates active-assignment constraint {name}")
            );
            assert_eq!(
                format!("{error:?}"),
                format!("Invariant {{ kind: AssignmentActive, constraint: Some({name:?}) }}")
            );
            assert_redacted(&error);
            for code in ["40001", "40P01"] {
                assert!(
                    matches!(map(Some(code), Some(name)), RegistryError::Retry(_)),
                    "{code}"
                );
            }
        }
        for name in [
            "service_grant_resource_server_assignment_fkey",
            "service_identity_resource_server_assignment_fkey",
        ] {
            let error = map(Some("23503"), Some(name));
            assert!(
                matches!(
                    error,
                    RegistryError::Invariant {
                        kind: InvariantKind::ForeignKey,
                        constraint: Some(constraint)
                    } if constraint == name
                ),
                "{error:?}"
            );
        }
        // Other checks of the same tables keep `Check`.
        let error = map(
            Some("23514"),
            Some("service_grant_resource_server_server_id_octet_length_check"),
        );
        assert!(
            matches!(
                error,
                RegistryError::Invariant {
                    kind: InvariantKind::Check,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn serialization_failure_and_deadlock_map_to_retry_with_the_raw_source() {
        for (code, constraint) in [
            ("40001", None),
            ("40P01", None),
            // A constraint name does not make it a constraint error.
            ("40001", Some("tenant_pkey")),
        ] {
            let error = map(Some(code), constraint);
            // Never StaleRevision: the caller retries the transaction.
            assert!(matches!(error, RegistryError::Retry(_)), "{error:?}");
            assert_eq!(
                error.to_string(),
                format!(
                    "registry transaction aborted (SQLSTATE {code}); retry the whole transaction"
                )
            );
            assert_eq!(
                format!("{error:?}"),
                format!(r#"Retry {{ sqlstate: Some("{code}"), .. }}"#)
            );
            assert_redacted(&error);
            let source = error
                .source()
                .and_then(|source| source.downcast_ref::<sqlx::Error>())
                .and_then(sqlx::Error::as_database_error)
                .expect("the raw database error");
            assert_eq!(source.code().as_deref(), Some(code));
            assert_eq!(source.message(), SECRET);
        }
        // Only those two: the other class 40 codes stay `Other`.
        for code in ["40000", "40002", "40003"] {
            assert!(
                matches!(map(Some(code), None), RegistryError::Other(_)),
                "{code}"
            );
        }
        let error = RegistryError::Retry(sqlx::Error::PoolTimedOut);
        assert_eq!(
            error.to_string(),
            "registry transaction aborted; retry the whole transaction"
        );
        assert_eq!(format!("{error:?}"), "Retry { sqlstate: None, .. }");
    }

    #[test]
    fn not_null_violation_maps_to_invariant_without_a_name() {
        let error = map(Some("23502"), None);
        assert!(matches!(
            error,
            RegistryError::Invariant {
                kind: InvariantKind::NotNull,
                constraint: None
            }
        ));
        assert_eq!(
            error.to_string(),
            "registry write violates a not-null constraint"
        );
    }

    #[test]
    fn guard_sqlstate_maps_to_guard() {
        let error = map(Some("SK001"), None);
        assert!(matches!(error, RegistryError::Guard));
        assert_eq!(
            error.to_string(),
            "registry write rejected by a schema guard (SK001)"
        );
        assert_redacted(&error);
    }

    #[test]
    fn unknown_constraints_and_codes_map_to_other_without_their_message() {
        for (code, constraint) in [
            (Some("23505"), Some("some_later_table_key")),
            (Some("23505"), None),
            (Some("23503"), Some("some_later_table_fkey")),
            (Some("23514"), None),
            (Some("54000"), None),
            (Some("P0001"), None),
            (None, Some("tenant_pkey")),
        ] {
            let error = map(code, constraint);
            assert!(matches!(error, RegistryError::Other(_)), "{error:?}");
            assert!(error.source().is_some());
            assert_redacted(&error);
        }
        let error = map(Some("54000"), None);
        assert_eq!(
            error.to_string(),
            "registry database error (SQLSTATE 54000)"
        );
        assert_eq!(
            format!("{error:?}"),
            r#"Other { sqlstate: Some("54000"), .. }"#
        );
    }

    #[test]
    fn non_database_errors_map_to_other() {
        let error = RegistryError::from(sqlx::Error::PoolTimedOut);
        assert!(matches!(error, RegistryError::Other(_)));
        assert_eq!(error.to_string(), "registry database error");
        assert_eq!(format!("{error:?}"), "Other { sqlstate: None, .. }");
    }

    #[test]
    fn an_unreadable_timestamp_names_table_and_column_but_not_the_row() {
        let error = RegistryError::from(sqlx::Error::ColumnDecode {
            index: "created_at_us".into(),
            source: Box::new(UnreadableTimestamp {
                table: "tenant",
                column: "created_at",
                id: "user-value-id".into(),
            }),
        });
        match &error {
            RegistryError::UnreadableTimestamp { table, column, id } => {
                assert_eq!(
                    (*table, *column, &id[..]),
                    ("tenant", "created_at", "user-value-id")
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            error.to_string(),
            "registry row has a tenant.created_at outside the readable timestamp range"
        );
        assert_eq!(
            format!("{error:?}"),
            r#"UnreadableTimestamp { table: "tenant", column: "created_at", .. }"#
        );
        assert_redacted(&error);
        assert!(error.source().is_none());
        // Any other decode error stays `Other`.
        let error = RegistryError::from(sqlx::Error::ColumnDecode {
            index: "created_at_us".into(),
            source: "timestamp out of range".into(),
        });
        assert!(matches!(error, RegistryError::Other(_)), "{error:?}");
    }

    #[test]
    fn the_decode_error_carrier_prints_no_row_id() {
        let carrier = UnreadableTimestamp {
            table: "tenant",
            column: "created_at",
            id: "user-value-id".into(),
        };
        assert_eq!(
            format!("{carrier:?}"),
            r#"UnreadableTimestamp { table: "tenant", column: "created_at", .. }"#
        );
        // Nor does the decode error that carries it.
        let error = sqlx::Error::ColumnDecode {
            index: "created_at_us".into(),
            source: Box::new(carrier),
        };
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("user-value"), "{text}");
        }
    }

    #[test]
    fn plain_outcomes_display_without_values() {
        assert_eq!(
            RegistryError::NotFound.to_string(),
            "registry row not found"
        );
        assert_eq!(format!("{:?}", RegistryError::NotFound), "NotFound");
        assert_eq!(
            RegistryError::StaleRevision.to_string(),
            "registry row is not at the expected revision; read it again"
        );
        assert_eq!(
            format!("{:?}", RegistryError::StaleRevision),
            "StaleRevision"
        );
        assert!(RegistryError::Guard.source().is_none());
    }

    #[test]
    fn a_reserved_actor_id_displays_without_the_id() {
        let error = RegistryError::ReservedActorId;
        assert_eq!(
            error.to_string(),
            "registry ID is reserved for an actor that is not an operator identity"
        );
        assert_eq!(format!("{error:?}"), "ReservedActorId");
        assert!(error.source().is_none());
    }

    #[test]
    fn a_required_predicate_displays_the_claim_and_the_problem() {
        assert_eq!(PredicateProblem::Missing.to_string(), "missing");
        assert_eq!(PredicateProblem::Empty.to_string(), "empty");
        let error = RegistryError::RequiredPredicate {
            claim: "repository_owner_id",
            problem: PredicateProblem::Missing,
        };
        assert_eq!(
            error.to_string(),
            "registry binding's required predicate repository_owner_id is missing"
        );
        assert_eq!(
            format!("{error:?}"),
            "RequiredPredicate { claim: \"repository_owner_id\", problem: Missing }"
        );
        assert!(error.source().is_none());
        let error = RegistryError::RequiredPredicate {
            claim: "sub",
            problem: PredicateProblem::Empty,
        };
        assert_eq!(
            error.to_string(),
            "registry binding's required predicate sub is empty"
        );
        assert_eq!(
            format!("{error:?}"),
            "RequiredPredicate { claim: \"sub\", problem: Empty }"
        );
    }
}
