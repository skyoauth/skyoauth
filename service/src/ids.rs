//! Server-generated opaque IDs (T10.2; identity-registry IR-020 to IR-024).
//!
//! Every object the registry creates gets an ID the service generates, never
//! one the client chooses (IR-020, IR-022). An ID is an opaque string
//! compared byte for byte (IR-024; OQ-IR-4): neither the service nor a
//! client or verifier parses it, so this module has no decode or parse
//! function, and the format below may change without notice. In particular
//! clients MUST NOT change the letter case of an ID: `ten_0abc…` and
//! `ten_0ABC…` are two different IDs.
//!
//! # Sources
//!
//! - Identity-registry IR-020: "All object IDs and public OAuth `client_id`
//!   values MUST be server-generated opaque random identifiers."
//! - IR-023: "ID prefixes indicate type, not authority. A verifier MUST NOT
//!   derive a profile, role or authorization from a prefix."
//! - IR-024: "IDs are opaque strings compared exactly (byte for byte). The
//!   prefixes and the length seen in examples are not part of a frozen ID
//!   format; clients and verifiers MUST NOT parse IDs or rely on a prefix or
//!   length."
//! - IR-057: the `instance_id` is a lowercase hyphenated UUIDv7, so it is not
//!   an [`IdKind`] here.
//!
//! # Format
//!
//! An ID is the kind's prefix ([`IdKind::prefix`]), one `_`, and a
//! [`ID_BODY_LEN`]-character body: the 128 random bits of 16 bytes, read
//! big-endian as one unsigned 128-bit number, written in Crockford's base32
//! alphabet [`ALPHABET`] (`0123456789abcdefghjkmnpqrstvwxyz`, without `i`,
//! `l`, `o` and `u`), most significant digit first, with no padding and no
//! check symbol. 26 digits hold 130 bits; the top two are zero, so the first
//! body character is one of `0` to `7`. The body is the ULID text layout in
//! lowercase (lead decision, 2026-11-24).
//!
//! - One letter case, lowercase, and nothing else: every ID matches
//!   `^[a-z]{3,4}_[0-9a-hjkmnp-tv-z]{26}$`, at most 31 bytes, well inside the
//!   255-byte bound every ID column has (migrations README, "What 0004
//!   adds"). Since IDs compare byte for byte, an upper-case spelling is
//!   another ID, not an alias (lead decision, 2026-11-24).
//! - The prefix is cosmetic: it helps a human reading a log or an export
//!   tell a tenant from a grant (IR-023), and nothing parses it
//!   (lead decision, 2026-11-24). The prefixes of the design's
//!   examples are kept where they have three or four letters (`ten`, `usr`,
//!   `wld`, `svc`, `adm`); the others are abbreviated to three or four
//!   letters (inferred).
//! - No generated ID is a reserved actor ID
//!   ([`is_reserved_actor_id`](crate::persistence::registry::is_reserved_actor_id)):
//!   the alphabet and every prefix lack `:`, so no ID begins with
//!   `recovery_key:`, and every ID is longer than `deployment_operator`. A
//!   test checks both for every kind.
//!
//! # Generators
//!
//! [`IdGenerator`] is the interface a write path takes. **It has no
//! production caller yet**: no registry writer or endpoint generates an ID
//! today, and the registry writers still take caller-supplied IDs
//! (migrations README, "Rust registry surface"). Slice S3a of M1a wires the
//! generator into the create paths. The production generator, which fills
//! the 16 bytes from the operating system's CSPRNG and calls [`encode_id`],
//! is not here yet either: it needs a dependency that awaits approval. Tests
//! use the deterministic generator `test_support::SequentialIds`, compiled
//! only with the `test-support` feature.

/// Crockford's base32 alphabet, lowercase: the digits, then the letters
/// without `i`, `l`, `o` and `u`.
pub const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// The length of an ID's body, after the prefix and its `_`: 26 base32
/// digits for 128 bits.
pub const ID_BODY_LEN: usize = 26;

/// What a generated ID identifies. Each kind is one table's own `id` column;
/// a principal has one kind per `principal.kind`.
///
/// Not a kind (inferred): the `instance_id` (a UUIDv7, IR-057); a service
/// identity, whose ID is its service principal's (`0004`); the rows keyed
/// by other IDs (the list rows, `recovery_state`, `audit_chain_head`) or by
/// a presented value (`consumed_assertion`, keyed by the assertion's `jti`).
/// Other server-generated opaque values, such as `Tenant.secret_namespace`
/// (IR-034) and a trust source's `cluster_id` (OQ-ADR011-1), and the objects
/// of later slices (OAuth clients, human providers) are not kinds yet: a
/// kind is added when its writer lands, with its own ruling on the
/// character set, since such a value may have to fit another syntax than an
/// ID's (lead decision, 2026-11-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// `tenant.id`.
    Tenant,
    /// `principal.id` of a `human` principal.
    HumanPrincipal,
    /// `principal.id` of a `workload` principal.
    WorkloadPrincipal,
    /// `principal.id` of a `service` principal, and so of its service
    /// identity.
    ServicePrincipal,
    /// `resource_server.id`.
    ResourceServer,
    /// `audience_tenant_assignment.id`.
    AudienceAssignment,
    /// `resource_server_checker.id`.
    Checker,
    /// `resource_action.id`.
    ResourceAction,
    /// `trust_keyset.id`.
    TrustKeyset,
    /// `trust_keyset_version.id`.
    TrustKeysetVersion,
    /// `trust_source.id`.
    TrustSource,
    /// `principal_binding.id`.
    PrincipalBinding,
    /// `service_grant.id`.
    ServiceGrant,
    /// `egress_allowlist_entry.id`.
    EgressEntry,
    /// `audit_event.id`.
    AuditEvent,
    /// `admin_identity.id`.
    AdminIdentity,
    /// `admin_credential.id`.
    AdminCredential,
    /// `admin_role_binding.id`.
    AdminRoleBinding,
    /// `administrative_operation.id`.
    AdministrativeOperation,
}

impl IdKind {
    /// Every kind, in declaration order.
    pub const ALL: [IdKind; 19] = [
        IdKind::Tenant,
        IdKind::HumanPrincipal,
        IdKind::WorkloadPrincipal,
        IdKind::ServicePrincipal,
        IdKind::ResourceServer,
        IdKind::AudienceAssignment,
        IdKind::Checker,
        IdKind::ResourceAction,
        IdKind::TrustKeyset,
        IdKind::TrustKeysetVersion,
        IdKind::TrustSource,
        IdKind::PrincipalBinding,
        IdKind::ServiceGrant,
        IdKind::EgressEntry,
        IdKind::AuditEvent,
        IdKind::AdminIdentity,
        IdKind::AdminCredential,
        IdKind::AdminRoleBinding,
        IdKind::AdministrativeOperation,
    ];

    /// The cosmetic prefix of this kind's IDs: three or four lowercase ASCII
    /// letters, different for every kind. It indicates type, not authority
    /// (IR-023), and nothing parses it (IR-024).
    pub const fn prefix(self) -> &'static str {
        match self {
            IdKind::Tenant => "ten",
            IdKind::HumanPrincipal => "usr",
            IdKind::WorkloadPrincipal => "wld",
            IdKind::ServicePrincipal => "svc",
            IdKind::ResourceServer => "rsrv",
            IdKind::AudienceAssignment => "asgn",
            IdKind::Checker => "chk",
            IdKind::ResourceAction => "act",
            IdKind::TrustKeyset => "kset",
            IdKind::TrustKeysetVersion => "kver",
            IdKind::TrustSource => "tsrc",
            IdKind::PrincipalBinding => "bind",
            IdKind::ServiceGrant => "grnt",
            IdKind::EgressEntry => "egr",
            IdKind::AuditEvent => "evt",
            IdKind::AdminIdentity => "adm",
            IdKind::AdminCredential => "cred",
            IdKind::AdminRoleBinding => "role",
            IdKind::AdministrativeOperation => "oper",
        }
    }
}

/// Generates the IDs of new objects. Every call returns a new ID; a write
/// path takes a `&dyn IdGenerator` (or a generic one) so tests can pass a
/// deterministic generator.
pub trait IdGenerator: Send + Sync {
    /// A new ID of `kind`, in the format of [`encode_id`].
    fn new_id(&self, kind: IdKind) -> String;
}

/// The ID of `kind` whose body encodes `random`: [`IdKind::prefix`], `_`
/// and the 26 lowercase Crockford base32 digits of the 16 bytes read as a
/// big-endian 128-bit number (see "Format" in the module documentation).
/// Pure and total: the generators call it with 16 bytes from their source.
pub fn encode_id(kind: IdKind, random: &[u8; 16]) -> String {
    let value = u128::from_be_bytes(*random);
    let prefix = kind.prefix();
    let mut id = String::with_capacity(prefix.len() + 1 + ID_BODY_LEN);
    id.push_str(prefix);
    id.push('_');
    // Digit `i` holds bits `125 - 5 * i` to `129 - 5 * i`; the first digit's
    // two top bits are beyond bit 127, so zero.
    for digit in 0..ID_BODY_LEN {
        let shift = 5 * (ID_BODY_LEN - 1 - digit);
        // The mask keeps the index below 32, the alphabet's length.
        let index = ((value >> shift) & 0x1f) as usize;
        id.push(char::from(ALPHABET[index]));
    }
    id
}

/// The deterministic [`IdGenerator`] of tests, compiled only with the
/// `test-support` feature (as `trust::test_support`). Nothing outside tests
/// may enable it, and no endpoint may use it.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    use std::sync::{Mutex, PoisonError};

    use super::{IdGenerator, IdKind, encode_id};

    /// A counter per [`IdKind`], starting at 1: the `n`th ID of a kind
    /// encodes the 16 bytes `seed` (8 bytes, big-endian) followed by `n`
    /// (8 bytes, big-endian). So two generators with the same seed give the
    /// same sequence for each kind whatever the interleaving of kinds, two
    /// seeds give disjoint IDs, and with seed 0 the first tenant is
    /// `ten_00000000000000000000000001`.
    #[derive(Debug)]
    pub struct SequentialIds {
        seed: u64,
        /// The last count of each kind, indexed by `kind as usize`.
        counters: Mutex<[u64; IdKind::ALL.len()]>,
    }

    impl SequentialIds {
        /// A generator with seed 0.
        pub fn new() -> Self {
            Self::with_seed(0)
        }

        /// A generator whose IDs carry `seed`, so that two generators used
        /// against one database never give the same ID.
        pub fn with_seed(seed: u64) -> Self {
            Self {
                seed,
                counters: Mutex::new([0; IdKind::ALL.len()]),
            }
        }
    }

    impl Default for SequentialIds {
        fn default() -> Self {
            Self::new()
        }
    }

    impl IdGenerator for SequentialIds {
        /// The next ID of `kind`.
        ///
        /// # Panics
        ///
        /// After `u64::MAX` IDs of one kind, rather than repeat one.
        fn new_id(&self, kind: IdKind) -> String {
            let count = {
                let mut counters = self.counters.lock().unwrap_or_else(PoisonError::into_inner);
                let counter = &mut counters[kind as usize];
                *counter = counter
                    .checked_add(1)
                    .expect("SequentialIds: counter exhausted");
                *counter
            };
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&self.seed.to_be_bytes());
            bytes[8..].copy_from_slice(&count.to_be_bytes());
            encode_id(kind, &bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::persistence::registry::{
        DEPLOYMENT_OPERATOR_ACTOR, RECOVERY_KEY_ACTOR_PREFIX, is_reserved_actor_id,
    };

    /// Byte patterns for the property checks: the extremes, single bits at
    /// both ends, and a few mixed patterns.
    fn patterns() -> Vec<[u8; 16]> {
        let mut patterns = vec![[0x00; 16], [0xff; 16], [0x55; 16], [0xaa; 16]];
        let mut ascending = [0u8; 16];
        for (i, byte) in ascending.iter_mut().enumerate() {
            *byte = i as u8;
        }
        patterns.push(ascending);
        for bit in [0, 1, 2, 63, 64, 125, 126, 127] {
            patterns.push((1u128 << bit).to_be_bytes());
        }
        patterns.push(u128::MAX.wrapping_sub(1).to_be_bytes());
        patterns
    }

    fn is_body_char(byte: u8) -> bool {
        matches!(byte, b'0'..=b'9' | b'a'..=b'h' | b'j' | b'k' | b'm' | b'n' | b'p'..=b't' | b'v'..=b'z')
    }

    /// Known answers, cross-checked with an independent encoder (Python's
    /// `int.from_bytes(b, "big")`, digit `i` = `(v >> (125 - 5 * i)) & 31`).
    #[test]
    fn known_answers() {
        let cases: [([u8; 16], &str); 6] = [
            ([0x00; 16], "ten_00000000000000000000000000"),
            ([0xff; 16], "ten_7zzzzzzzzzzzzzzzzzzzzzzzzz"),
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                "ten_00041061050r3gg28a1c60t3gf",
            ),
            (
                0x0193_a1b2_c3d4_e5f6_0718_293a_4b5c_6d7e_u128.to_be_bytes(),
                "ten_01jegv5gymwqv0e619795nrvby",
            ),
            (
                (1u128 << 127).to_be_bytes(),
                "ten_40000000000000000000000000",
            ),
            (1u128.to_be_bytes(), "ten_00000000000000000000000001"),
        ];
        for (bytes, expected) in cases {
            assert_eq!(encode_id(IdKind::Tenant, &bytes), expected);
        }
        // The digit values 6 to 31, then 0 to 7 three times and 0, 1: so
        // every alphabet position is pinned.
        let mut value = 0u128;
        for digit in 6..32u128 {
            value = (value << 5) | digit;
        }
        assert_eq!(
            encode_id(IdKind::Checker, &value.to_be_bytes()),
            "chk_6789abcdefghjkmnpqrstvwxyz"
        );
        let mut value = 0u128;
        for digit in 0..26u128 {
            value = (value << 5) | (digit % 8);
        }
        assert_eq!(
            encode_id(IdKind::Checker, &value.to_be_bytes()),
            "chk_01234567012345670123456701"
        );
    }

    #[test]
    fn the_alphabet_is_crockford_lowercase() {
        assert_eq!(ALPHABET.len(), 32);
        assert!(ALPHABET.iter().all(|&b| is_body_char(b)));
        assert_eq!(ALPHABET.iter().collect::<HashSet<_>>().len(), 32);
        assert!(ALPHABET.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn every_kind_has_a_distinct_short_lowercase_prefix() {
        let mut prefixes = HashSet::new();
        for kind in IdKind::ALL {
            let prefix = kind.prefix();
            assert!((3..=4).contains(&prefix.len()), "{kind:?}");
            assert!(prefix.bytes().all(|b| b.is_ascii_lowercase()), "{kind:?}");
            assert!(prefixes.insert(prefix), "{kind:?}");
        }
        // `ALL` lists every kind once, in declaration order, so `kind as
        // usize` indexes it.
        for (index, kind) in IdKind::ALL.into_iter().enumerate() {
            assert_eq!(kind as usize, index);
        }
    }

    /// Length, character set, case and prefix for every kind and pattern.
    #[test]
    fn every_id_is_prefix_underscore_and_26_lowercase_digits() {
        for kind in IdKind::ALL {
            for bytes in patterns() {
                let id = encode_id(kind, &bytes);
                let (prefix, body) = id.split_at(kind.prefix().len());
                assert_eq!(prefix, kind.prefix(), "{id}");
                let body = body.strip_prefix('_').expect(&id);
                assert_eq!(body.len(), ID_BODY_LEN, "{id}");
                assert!(body.bytes().all(is_body_char), "{id}");
                assert!(matches!(body.as_bytes()[0], b'0'..=b'7'), "{id}");
                assert_eq!(id, id.to_ascii_lowercase(), "{id}");
                assert!(id.len() <= 31 && id.is_ascii(), "{id}");
            }
        }
    }

    /// Different bytes give different IDs, and the encoding is the same for
    /// the same input.
    #[test]
    fn the_encoding_is_injective_on_the_patterns() {
        let ids: HashSet<String> = patterns()
            .iter()
            .map(|b| encode_id(IdKind::AuditEvent, b))
            .collect();
        assert_eq!(ids.len(), patterns().len());
        for bytes in patterns() {
            assert_eq!(
                encode_id(IdKind::AuditEvent, &bytes),
                encode_id(IdKind::AuditEvent, &bytes)
            );
        }
    }

    /// No generated ID is reserved, by construction: `is_reserved_actor_id`
    /// reserves exactly `deployment_operator` and every ID beginning with
    /// `recovery_key:`. No prefix and no alphabet character is `:`, and every
    /// ID is longer than `deployment_operator`.
    #[test]
    fn no_generated_id_is_a_reserved_actor_id() {
        assert!(RECOVERY_KEY_ACTOR_PREFIX.contains(':'));
        assert!(!ALPHABET.contains(&b':'));
        for kind in IdKind::ALL {
            assert!(!kind.prefix().contains(':'), "{kind:?}");
            assert!(
                kind.prefix().len() + 1 + ID_BODY_LEN > DEPLOYMENT_OPERATOR_ACTOR.len(),
                "{kind:?}"
            );
            for bytes in patterns() {
                let id = encode_id(kind, &bytes);
                assert!(!is_reserved_actor_id(&id), "{id}");
                assert!(!id.contains(':'), "{id}");
            }
        }
    }

    #[cfg(feature = "test-support")]
    mod sequential {
        use super::super::{IdGenerator, IdKind, test_support::SequentialIds};
        use std::collections::HashSet;

        #[test]
        fn counts_per_kind_from_one() {
            let ids = SequentialIds::new();
            assert_eq!(ids.new_id(IdKind::Tenant), "ten_00000000000000000000000001");
            assert_eq!(
                ids.new_id(IdKind::WorkloadPrincipal),
                "wld_00000000000000000000000001"
            );
            assert_eq!(ids.new_id(IdKind::Tenant), "ten_00000000000000000000000002");
            let seeded = SequentialIds::with_seed(1);
            // The seed is the high 64 bits: 2^64 + 1.
            assert_eq!(
                seeded.new_id(IdKind::Tenant),
                "ten_0000000000000g000000000001"
            );
        }

        #[test]
        fn is_reproducible_whatever_the_interleaving() {
            let first = SequentialIds::with_seed(7);
            let second = SequentialIds::with_seed(7);
            let a: Vec<String> = (0..5).map(|_| first.new_id(IdKind::ServiceGrant)).collect();
            // Other kinds in between do not move the grant counter.
            let mut b = Vec::new();
            for _ in 0..5 {
                second.new_id(IdKind::AuditEvent);
                b.push(second.new_id(IdKind::ServiceGrant));
            }
            assert_eq!(a, b);
        }

        #[test]
        fn gives_distinct_ids_across_kinds_counts_and_seeds() {
            let mut seen = HashSet::new();
            for seed in [0, 1, u64::MAX] {
                let ids = SequentialIds::with_seed(seed);
                for kind in IdKind::ALL {
                    for _ in 0..50 {
                        let id = ids.new_id(kind);
                        assert!(id.starts_with(kind.prefix()), "{id}");
                        assert!(seen.insert(id.clone()), "{id}");
                    }
                }
            }
            assert_eq!(seen.len(), 3 * IdKind::ALL.len() * 50);
        }

        #[test]
        fn is_send_and_sync() {
            fn generator(_: &dyn IdGenerator) {}
            generator(&SequentialIds::default());
        }
    }
}
