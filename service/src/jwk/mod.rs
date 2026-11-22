//! Validation of uploaded public JWK Sets for `uploaded_jwks` trust sources
//! (T11.3): public-only keys, algorithms, strength and size, RFC 7638
//! thumbprints, explicit overlap and unique, nonconflicting `kid`s across
//! keyset versions.
//!
//! This module is pure: no I/O, no clock (time is a parameter) and no
//! dependency on the registry. `persistence::registry` may depend on it,
//! never the reverse (as for `policy`, lead ruling, 2026-11-21). Nothing
//! calls it yet, and it must not be the only validation of a keyset write
//! until the gate under "Follow-ups" is met.
//!
//! # Sources
//!
//! - Tasks T11.3: "Uploaded public-only keys, algorithms/strength/size,
//!   explicit overlap, unique nonconflicting live kid; reject private
//!   parameters."
//! - ADR-005 item 1 (the three source kinds): "`uploaded_jwks`: exact
//!   issuer, audiences and algorithms, and a stable tenant-owned
//!   `TrustKeyset` parent with public-only versioned keysets and explicit
//!   overlap. Several versions may be active; conflicting live kid/key
//!   combinations deny; private key parameters are rejected (T11.3,
//!   T11.9)."
//! - ADR-005 item 5 (keyset parent): "`TrustKeysetVersion` rows carry
//!   public-only keys with explicit validity."
//! - ADR-005 item 8: "Unregistered sources, token `jku`/`x5u`/embedded-key
//!   trust, `alg=none`, weak algorithm substitution, private-key uploads and
//!   arbitrary redirects are rejected." Design section 5.4 says the same:
//!   "Reject unregistered sources, token `jku`/`x5u`/embedded-key trust,
//!   `alg=none`, weak substitution, private-key uploads and arbitrary
//!   redirects."
//! - The migrations README, "Keysets and versions": the `0004` `CHECK`
//!   already rejects a set whose `keys` is not a nonempty array of objects
//!   and any key with the members `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or
//!   `k`; this module repeats those checks so it stands alone.
//! - RFC 7517 (JWK), RFC 7518 section 6 (key parameters), RFC 7638
//!   (thumbprints), RFC 8037 (`OKP`, Ed25519) and RFC 8725 section 3.1
//!   (one algorithm per key).
//!
//! Every pick below is a lead decision dated 2026-11-21, provisional until
//! the maintainer ratifies the ADRs (T00.8 to T00.17). A pick no source
//! states is marked "(inferred)".
//!
//! # Rules
//!
//! A set ([`parse_jwk_set`]):
//!
//! - is a JSON object whose `keys` is a nonempty array of objects, with no
//!   other member (inferred);
//! - is at most [`MAX_SET_BYTES`] (64 KiB) in compact JSON and holds at
//!   most [`MAX_KEYS`] (20) keys (both inferred). The size is measured on
//!   the parsed value only, as an early cut-off: a set within the other
//!   rules is at most 34,290 bytes (20 RSA keys of 8192 bits with a 32-octet
//!   `e`, a 128-byte `kid` and every allowlisted member; a test builds it),
//!   so a raw request-body limit of 64 KiB in the wiring is consistent.
//!   Bounding the raw body before parsing is the caller's (see
//!   "Follow-ups"). Duplicate member names are
//!   resolved by the JSON parser (`serde_json` and `jsonb` both keep the
//!   last), not seen here;
//! - has no two keys with the same `kid`, and (inferred) no two keys with
//!   the same thumbprint under different `kid`s, the in-set form of the
//!   cross-version key conflict below.
//!
//! A key:
//!
//! - has none of the private or symmetric members [`PRIVATE_MEMBERS`]
//!   (case-sensitive, whatever their value), checked first, so the error
//!   names the member and nothing else of the key;
//! - has none of [`KEY_REFERENCE_MEMBERS`] (`x5u`, `x5c`, `jku`)
//!   (inferred: the sources reject token `jku`/`x5u`/embedded-key trust,
//!   ADR-005 item 8 and design section 5.4 quoted above, and do not speak
//!   of these members in an uploaded JWK, nor of `x5c` at all; rejecting
//!   them keeps an upload from carrying references or certificates that
//!   could later be read as trust);
//! - has `kty` `RSA`, `EC` or `OKP` (inferred: `oct` and every other type,
//!   the post-quantum types included, are refused);
//! - has only allowlisted members (inferred): [`COMMON_MEMBERS`] (`kty`,
//!   `kid`, `use`, `key_ops`, `alg`, `x5t`, `x5t#S256`) and its type's
//!   [`RSA_MEMBERS`] (`n`, `e`), [`EC_MEMBERS`] (`crv`, `x`, `y`) or
//!   [`OKP_MEMBERS`] (`crv`, `x`). Any other member, unknown ones
//!   included, is refused with [`JwkError::UnexpectedMember`], which does
//!   not name it (the name is uploaded text);
//! - has a `kid` (required: inferred from T11.3's "unique nonconflicting
//!   live kid") of 1 to [`KID_MAX_BYTES`] (128) bytes of `A`-`Z`, `a`-`z`,
//!   `0`-`9` and `-._~:+/=` (inferred: the URI unreserved characters, `:`,
//!   and the standard base64 characters some issuers use in `kid`s);
//! - has `use` absent or `sig`, and `key_ops` absent or exactly
//!   `["verify"]` (both may be present, as RFC 7517 section 4.3 permits
//!   when consistent; inferred);
//! - has `x5t` and `x5t#S256`, when present, as canonical base64url of
//!   exactly 20 and 32 octets (inferred: they are certificate thumbprints,
//!   RFC 7517 sections 4.8 and 4.9, checked so they carry nothing else, and
//!   otherwise unused);
//! - has its key members as canonical unpadded base64url: no padding, no
//!   character outside the URL-safe alphabet (so no whitespace, `+` or
//!   `/`), not empty, and (inferred) no nonzero trailing bits;
//! - `RSA`: `n` and `e` without leading zero octets (RFC 7518 section
//!   6.3.1), a modulus of [`RSA_MIN_MODULUS_BITS`] (2048, inferred) to
//!   [`RSA_MAX_MODULUS_BITS`] (8192, inferred) bits, odd (inferred); `e`
//!   odd, at least [`RSA_MIN_EXPONENT`] (65537) and at most
//!   [`RSA_MAX_EXPONENT_OCTETS`] (32) octets, the FIPS 186-4 appendix B.3.1
//!   bounds (inferred);
//! - `EC`: `crv` `P-256`, `P-384` or `P-521` with `x` and `y` exactly 32,
//!   48 or 66 octets (RFC 7518 section 6.2.1); `secp256k1` and every other
//!   curve are refused (inferred);
//! - `OKP`: `crv` `Ed25519` with `x` exactly 32 octets; `Ed448`, `X25519`,
//!   `X448` and every other curve are refused (inferred);
//! - has `alg`, when present, in the allowed set and consistent with its
//!   type and curve: `RS256` or `PS256` for `RSA`, `ES256` for `P-256`,
//!   `ES384` for `P-384`, `ES512` for `P-521`, `EdDSA` for `Ed25519`;
//!   `none` and `HS*` never (ADR-005 item 8). Names parse against
//!   [`KNOWN_ALGORITHMS`], whatever the allowed set. A key whose type admits
//!   more than one algorithm (every RSA key: RS256 and PS256) must carry
//!   `alg`, whatever the allowed set; an EC or Ed25519 key may omit it,
//!   since its curve fixes the algorithm, which must then be allowed
//!   (inferred: one algorithm per key, RFC 8725 section 3.1).
//!   [`PublicJwk::algorithm`] is that one algorithm: the `alg` member or the
//!   curve's algorithm. The allowed set is a parameter; its default
//!   [`DEFAULT_ALLOWED_ALGORITHMS`] (`RS256`, `PS256`, `ES256`, `ES384`,
//!   `ES512`, `EdDSA`) is provisional: the set is OQ-TP-3, open for the
//!   maintainer.
//!
//! Every accepted key gets its RFC 7638 SHA-256 [`Thumbprint`] (see the
//! `thumbprint` submodule).
//!
//! # Versions
//!
//! A version's window is `[effective_at, expires_at)`: start inclusive,
//! expiry exclusive, no expiry for `None`, and empty when the expiry is not
//! after the start (all inferred). Three rules make two versions conflict
//! ("conflicting live kid/key combinations deny"): one `kid` with two
//! different keys (thumbprints), one key under two different `kid`s, and
//! (inferred) one `kid` and key with two different algorithms
//! ([`PublicJwk::algorithm`], so a curve key without `alg` and the same key
//! with its curve's `alg` do not conflict). One `kid` with the same key and
//! algorithm in several versions is the explicit overlap.
//!
//! - [`check_version_overlap`] runs at every point where a version becomes
//!   enabled (inferred): creation as enabled, re-enable, and any import or
//!   restore path; creating a disabled version may skip it. It compares
//!   that version with every other enabled version whose window intersects
//!   its own (it skips disabled versions and any entry with the checked
//!   version's ID itself), so a conflict that would arise later (a future
//!   start) is
//!   refused up front. The writes of one keyset must be serialized for it
//!   to hold (see "Follow-ups").
//! - [`live_keys`] runs at verification time: the versions enabled and
//!   live at `at`, merged into one list sorted by `kid`. One conflict
//!   denies the whole live set (inferred). It is the runtime backstop and
//!   does not replace the enabling check: on its own it sees a conflict
//!   only once both versions are live.
//!
//! Rotation (inferred): validity windows are immutable in the registry,
//! so disabling is the only way to retire a version, an open-ended one
//! included. To replace the key of a `kid`, disable the old open-ended
//! version and write the replacement with the same `kid`; re-enabling the
//! old version is refused while the replacement is enabled.
//!
//! # Errors
//!
//! [`JwkSetError`], [`JwkError`] and [`OverlapError`] name a fixed member
//! name, the key's index, the `kid` and the version IDs, never key material
//! or an uploaded member name: no variant holds `n`, `e`, `x`, `y`, key
//! octets, an unexpected member's name or the JWK, so neither `Display`
//! nor `Debug` can print them. [`PublicKey`] and [`PublicJwk`] implement
//! `Debug` by hand and print no key octets either.
//!
//! # Test vectors
//!
//! rfc-editor.org was not reachable when this was written, so the vectors
//! are not copied from the RFC text. The RFC 7638 RSA key and the RFC 8037
//! Ed25519 key (appendix A.3) are the values known from those documents,
//! and Python's `hashlib` reproduces their published thumbprints
//! independently. The RFC 7517 appendix A.1 P-256 key has no published
//! thumbprint: its thumbprint, and those of the generated P-384 and P-521
//! keys, were computed with Python (`hashlib`, `cryptography`), never from
//! this module's output. See `service/tests/jwk.rs`.
//!
//! # Follow-ups
//!
//! - **Gate.** This module must not be the only validation on any keyset
//!   write path (T11.9, T24.2) until (a) EC points are checked on-curve
//!   with `x`, `y` < p and (b) Ed25519 keys are canonical (y < p) and not
//!   small-order, or the write path also imports each key with the
//!   verifying crate in strict mode and refuses keys it cannot import.
//!   T11.7 must use strict Ed25519 verification. T24.3's "fake keys"
//!   negative is the acceptance test. Today only lengths are checked: the
//!   module accepts the P-256 point (0, 0), a P-521 coordinate >= p and
//!   the Ed25519 identity point (pinned by a test that must flip when the
//!   check lands).
//! - The wiring PR must bound the raw request body before parsing it: this
//!   module bounds only the parsed value.
//! - The allowed algorithm set (OQ-TP-3, open) and its intersection with a
//!   source's `algorithms` allowlist.
//! - Wiring into the trust keyset write path (T11.9, T24.2): calling
//!   [`parse_jwk_set`] at write and [`check_version_overlap`] wherever a
//!   version becomes enabled (creation as enabled, re-enable, import,
//!   restore), serializing the writes of one keyset (lock the parent
//!   keyset row or advance its revision), and deciding what the version's
//!   `fingerprint` column holds: this module does not define it. Nothing
//!   calls this module yet.
//! - Whether validity windows should stay immutable, so that an operator
//!   could close an open-ended window instead of disabling the version
//!   (open question).
//! - Selecting the live verification key of the explicitly selected source
//!   (T11.7) from [`live_keys`].

mod base64url;
mod key;
mod overlap;
mod set;
mod thumbprint;

pub use base64url::Base64urlError;
pub use key::{
    Algorithm, COMMON_MEMBERS, DEFAULT_ALLOWED_ALGORITHMS, EC_MEMBERS, EcCurve, JwkError,
    KEY_REFERENCE_MEMBERS, KID_MAX_BYTES, KNOWN_ALGORITHMS, Kid, OKP_MEMBERS, OkpCurve,
    PRIVATE_MEMBERS, PublicJwk, PublicKey, RSA_MAX_EXPONENT_OCTETS, RSA_MAX_MODULUS_BITS,
    RSA_MEMBERS, RSA_MIN_EXPONENT, RSA_MIN_MODULUS_BITS,
};
pub use overlap::{
    KeysetVersion, LiveKey, OverlapError, VersionStatus, check_version_overlap, live_keys,
};
pub use set::{JwkSet, JwkSetError, MAX_KEYS, MAX_SET_BYTES, parse_jwk_set};
pub use thumbprint::Thumbprint;
