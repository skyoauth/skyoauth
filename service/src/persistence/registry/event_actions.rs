//! The closed table of audit event actions (identity-registry IR-059,
//! OQ-IR-15).
//!
//! [`AUDIT_ACTIONS`] is the closed set of action names and the one place
//! they live (lead decision, 2026-11-21, provisional until the maintainer
//! ratifies the ADRs, T00.8 to T00.17, Gate M0; OQ-IR-15). IR-059's
//! three-row table gives examples, all of them in the set; every other name
//! is (inferred), named here as OQ-IR-15 asks the audit writer to do:
//!
//! - The startup event that mirrors `single_actor_mode` (IR-053) is
//!   `instance_security_policy.mirror`, and the sink-change event (IR-053)
//!   is `instance_security_policy.change_sink`: both write the
//!   `InstanceSecurityPolicy` row (IR-059), so `<resource>` is that row's.
//! - First bootstrap (IR-057; design section 7.2; T13.4) writes one
//!   event, `recovery_state.create`, with the `instance_id` as `object_id`,
//!   also when it inserts the policy row (provisional lead pick,
//!   2026-11-21; identity-registry section 5.2).
//!   `instance_security_policy.create` stays in the table for a later
//!   startup path that creates the policy row. A recovery key rotation
//!   (OQ-TM-8) is `recovery_state.rotate_key`. The break-glass operator
//!   restoration (T13.5) writes two events in one savepoint (lead ruling,
//!   2026-11-21, provisional): `admin_identity.restore`, which also records
//!   the consume and the revocations (inferred), then
//!   `recovery_state.rotate_key` for the key it rotates. The issue of a
//!   recovery challenge, which inserts its `administrative_operation` row,
//!   is `administrative_operation.create` (inferred: the `create` verb of an
//!   insert; added with the recovery registry, PR 3a). The T13.3
//!   operations (an IR-054 approval, say) will write the same name when
//!   they insert theirs, so a consumer tells them apart by joining the
//!   event's `object_id` to the operation row and reading its `kind`.
//! - The IR-152 egress entry writes are a create and a `status` change:
//!   `egress_allowlist_entry.create`, `.enable` (IR-059) and `.disable`.
//! - The T13.3 administrative events of M1a are the writes of the operator
//!   API (public-api section 7.1) on the tables that exist: operators
//!   (`admin_identity`), their credentials (`admin_credential`) and role
//!   bindings (`admin_role_binding`), an IR-054 approval
//!   (`administrative_operation.approve`), and the workload registry tables
//!   of `0002` to `0004`.
//!
//! Each table has the verbs its writes allow: `create` for an insert,
//! `enable` and `disable` for a write that changes only `status` (as
//! IR-059's `egress_allowlist_entry.enable`), `update` for any other write
//! of the row (a list-set change included, since it advances the owner's
//! revision), and `delete` where `0006` allows one (a disabled binding or
//! grant). One writer departs from this: [`crate::trust::update_source`]
//! records every trust source update as `trust_source.update`, a
//! status-only one included (provisional lead pick, 2026-11-22, open), so
//! `trust_source.enable` and `trust_source.disable` are listed but have no
//! writer yet. Human, gateway, key and
//! provider-switch actions (M1b and later) are not listed yet; each lands
//! with its writer.
//!
//! The syntax is IR-059's `<resource>.<verb>`: `<resource>` is the entity's
//! name in lowercase snake case, and `<verb>` is lowercase snake case too
//! (inferred): both match `[a-z][a-z0-9_]*`, joined by one dot.
//! [`append_audit_event`](super::append_audit_event) rejects a name with
//! another syntax or not in the table before any statement runs (lead
//! decision, 2026-11-21: a closed list).

/// Every audit action name, sorted byte-wise (see the module docs).
pub const AUDIT_ACTIONS: &[&str] = &[
    "admin_credential.create",
    "admin_credential.disable",
    "admin_identity.create",
    "admin_identity.disable",
    "admin_identity.enable",
    "admin_identity.restore",
    "admin_role_binding.create",
    "admin_role_binding.disable",
    "admin_role_binding.enable",
    "administrative_operation.approve",
    "administrative_operation.create",
    "audience_tenant_assignment.create",
    "audience_tenant_assignment.disable",
    "audience_tenant_assignment.enable",
    "audience_tenant_assignment.update",
    "egress_allowlist_entry.create",
    "egress_allowlist_entry.disable",
    // IR-059.
    "egress_allowlist_entry.enable",
    "instance_security_policy.change_sink",
    "instance_security_policy.create",
    "instance_security_policy.mirror",
    // IR-059.
    "instance_security_policy.update",
    "principal.create",
    "principal.disable",
    "principal.enable",
    "principal.update",
    "principal_binding.create",
    "principal_binding.delete",
    "principal_binding.disable",
    "principal_binding.enable",
    "principal_binding.update",
    "recovery_state.create",
    "recovery_state.rotate_key",
    "resource_action.create",
    "resource_action.disable",
    "resource_action.enable",
    "resource_action.update",
    "resource_server.create",
    "resource_server.disable",
    "resource_server.enable",
    "resource_server.update",
    "resource_server_checker.create",
    "resource_server_checker.disable",
    "resource_server_checker.enable",
    "resource_server_checker.update",
    "service_grant.create",
    "service_grant.delete",
    "service_grant.disable",
    "service_grant.enable",
    "service_grant.update",
    "service_identity.create",
    "service_identity.disable",
    "service_identity.enable",
    "service_identity.update",
    // IR-059.
    "tenant.create",
    "tenant.disable",
    "tenant.enable",
    "tenant.update",
    "trust_keyset.create",
    "trust_keyset.disable",
    "trust_keyset.enable",
    "trust_keyset.update",
    "trust_keyset_version.create",
    "trust_keyset_version.disable",
    "trust_keyset_version.enable",
    "trust_source.create",
    "trust_source.disable",
    "trust_source.enable",
    "trust_source.update",
];

/// Whether `name` has the `<resource>.<verb>` syntax: two lowercase snake
/// case words, each `[a-z][a-z0-9_]*`, joined by one dot.
pub fn is_audit_action_syntax(name: &str) -> bool {
    let word = |part: &str| {
        let mut bytes = part.bytes();
        bytes.next().is_some_and(|first| first.is_ascii_lowercase())
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };
    match name.split_once('.') {
        Some((resource, verb)) => word(resource) && word(verb),
        None => false,
    }
}

/// Whether `name` is in [`AUDIT_ACTIONS`].
pub fn is_audit_action(name: &str) -> bool {
    AUDIT_ACTIONS.binary_search(&name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_unique_and_well_formed() {
        assert!(AUDIT_ACTIONS.windows(2).all(|w| w[0] < w[1]));
        for name in AUDIT_ACTIONS {
            assert!(is_audit_action_syntax(name), "{name}");
            assert!(is_audit_action(name), "{name}");
        }
        // IR-059's table.
        for name in [
            "tenant.create",
            "instance_security_policy.update",
            "egress_allowlist_entry.enable",
        ] {
            assert!(is_audit_action(name), "{name}");
        }
    }

    #[test]
    fn the_syntax_is_two_lowercase_snake_case_words() {
        for name in [
            "tenant.create",
            "a.b",
            "a1_b.c_2",
            "recovery_state.rotate_key",
        ] {
            assert!(is_audit_action_syntax(name), "{name}");
        }
        for name in [
            "",
            ".",
            "tenant",
            "tenant.",
            ".create",
            "Tenant.create",
            "tenant.Create",
            "tenant.create.extra",
            "tenant..create",
            "tenant-x.create",
            "1tenant.create",
            "tenant._create",
            "_tenant.create",
            "tenant.create ",
            " tenant.create",
            "tenant.cre\u{0}ate",
            "tenant.creaté",
        ] {
            assert!(!is_audit_action_syntax(name), "{name:?}");
        }
        assert!(!is_audit_action("tenant.delete"));
        assert!(!is_audit_action("Tenant.create"));
    }
}
