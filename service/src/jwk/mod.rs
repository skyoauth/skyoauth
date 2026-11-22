//! Validation of uploaded public JWK Sets for `uploaded_jwks` trust sources
//! (T11.3): public-only keys, algorithms, strength and size, RFC 7638
//! thumbprints, explicit overlap and unique, nonconflicting live `kid`s
//! across keyset versions.
//!
//! This module is pure: no I/O, no clock (time is a parameter) and no
//! dependency on the registry. `persistence::registry` may depend on it,
//! never the reverse (as for `policy`, lead ruling, 2026-11-21).
//!
//! # Sources
//!
//! - Tasks T11.3: "Uploaded public-only keys, algorithms/strength/size,
//!   explicit overlap, unique nonconflicting live kid; reject private
//!   parameters."
//! - ADR-005 item 2: "`uploaded_jwks`: exact issuer, audiences and
//!   algorithms, and a stable tenant-owned `TrustKeyset` parent with
//!   public-only versioned keysets and explicit overlap. Several versions
//!   may be active; conflicting live kid/key combinations deny; private key
//!   parameters are rejected (T11.3, T11.9)."
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
//!   (thumbprints) and RFC 8037 (`OKP`, Ed25519).
//!
//! Every pick below is a lead decision dated 2026-11-21, provisional until
//! the maintainer ratifies the ADRs (T00.8 to T00.17). A pick no source
//! states is marked "inferred".
//!
//! # Rules
//!
//! A set ([`parse_jwk_set`]):
//!
//! - is a JSON object whose `keys` is a nonempty array of objects;
//! - is at most [`MAX_SET_BYTES`] (64 KiB) in compact JSON and holds at
//!   most [`MAX_KEYS`] (20) keys (both inferred). The size is measured on
//!   the parsed value; the caller bounds the raw request body before
//!   parsing it. Duplicate member names are resolved by the JSON parser
//!   (`serde_json` and `jsonb` both keep the last), not seen here;
//! - has no two keys with the same `kid`, and (inferred) no two keys with
//!   the same thumbprint under different `kid`s, the in-set form of the
//!   cross-version key conflict below.
//!
//! A key:
//!
//! - has none of the private or symmetric members [`PRIVATE_MEMBERS`]
//!   (case-sensitive), checked first, so the error names the member and
//!   nothing else of the key;
//! - has none of [`KEY_REFERENCE_MEMBERS`] (`x5u`, `x5c`, `jku`). Inferred:
//!   the sources reject token `jku`/`x5u`/embedded-key trust (ADR-005 item
//!   8, design section 5.4, quoted above) and do not speak of these members
//!   in an uploaded JWK, nor of `x5c` at all; rejecting them keeps an
//!   upload from carrying references or certificates that could later be
//!   read as trust;
//! - has `kty` `RSA`, `EC` or `OKP` (`oct` and every other type, the
//!   post-quantum types included, are refused);
//! - has a `kid` (required: inferred from T11.3's "unique nonconflicting
//!   live kid") of 1 to [`KID_MAX_BYTES`] (128) bytes of `A`-`Z`, `a`-`z`,
//!   `0`-`9` and `-._~:+/=` (inferred: the URI unreserved characters, `:`,
//!   and the standard base64 characters some issuers use in `kid`s);
//! - has `use` absent or `sig`, and `key_ops` absent or exactly
//!   `["verify"]` (both may be present, as RFC 7517 section 4.3 permits
//!   when consistent; inferred);
//! - has its required key members as canonical unpadded base64url: no
//!   padding, no character outside the URL-safe alphabet (so no
//!   whitespace, `+` or `/`), not empty, no nonzero trailing bits;
//! - `RSA`: `n` and `e` without leading zero octets (RFC 7518 section
//!   6.3.1), a modulus of [`RSA_MIN_MODULUS_BITS`] (2048) to
//!   [`RSA_MAX_MODULUS_BITS`] (8192, inferred) bits, odd (inferred); `e`
//!   odd, at least [`RSA_MIN_EXPONENT`] (65537) and at most
//!   [`RSA_MAX_EXPONENT_OCTETS`] (32) octets, the FIPS 186-4 appendix B.3.1
//!   bounds (inferred);
//! - `EC`: `crv` `P-256`, `P-384` or `P-521` with `x` and `y` exactly 32,
//!   48 or 66 octets (RFC 7518 section 6.2.1); `secp256k1` and every other
//!   curve are refused;
//! - `OKP`: `crv` `Ed25519` with `x` exactly 32 octets; `Ed448`, `X25519`,
//!   `X448` and every other curve are refused;
//! - has `alg`, when present, in the allowed set and consistent with its
//!   type and curve: `RS256` or `PS256` for `RSA`, `ES256` for `P-256`,
//!   `ES384` for `P-384`, `ES512` for `P-521`, `EdDSA` for `Ed25519`;
//!   `none` and `HS*` never (ADR-005 item 8). Without `alg`, a key is
//!   accepted when its type and curve admit at least one allowed
//!   algorithm. The allowed set is a parameter; its default
//!   [`DEFAULT_ALLOWED_ALGORITHMS`] (`RS256`, `PS256`, `ES256`, `ES384`,
//!   `ES512`, `EdDSA`) is provisional: the set is OQ-TP-3, open for the
//!   maintainer;
//! - may carry any other member, which is ignored (`x5t`, `x5t#S256`,
//!   `ext` and so on).
//!
//! Every accepted key gets its RFC 7638 SHA-256 [`Thumbprint`] (see the
//! `thumbprint` submodule).
//!
//! Across versions ([`live_keys`]): a version is live at `at` when it is
//! enabled and `effective_at <= at < expires_at` (start inclusive, expiry
//! exclusive, no expiry for `None`; inferred). Among the live versions, one
//! `kid` with two different keys (thumbprints) and one key under two
//! different `kid`s are conflicts ("conflicting live kid/key combinations
//! deny"); one `kid` with the same key in several live versions is the
//! explicit overlap and is merged. Inferred: the same `kid` and key with
//! different `alg` members (an absent `alg` counting as different) is a
//! conflict too. The result is sorted by `kid` byte-wise.
//!
//! # Errors
//!
//! [`JwkSetError`], [`JwkError`] and [`OverlapError`] name the member,
//! the key's index, the `kid` and the version IDs, never key material:
//! no variant holds `n`, `e`, `x`, `y`, key octets or the JWK, so neither
//! `Display` nor `Debug` can print them. [`PublicKey`] and [`PublicJwk`]
//! implement `Debug` by hand and print no key octets either.
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
//! - The on-curve check of `EC` points and the field-range check of their
//!   coordinates, and the Ed25519 point decoding check: only lengths are
//!   checked here, since no curve crate is a dependency.
//! - The allowed algorithm set (OQ-TP-3, open) and its intersection with a
//!   source's `algorithms` allowlist.
//! - Wiring into the trust keyset write path (T11.9, T24.2), including
//!   what the version's `fingerprint` column holds: nothing calls this
//!   module yet.
//! - Selecting the live verification key of the explicitly selected source
//!   (T11.7) from [`live_keys`].

mod base64url;
mod key;
mod overlap;
mod set;
mod thumbprint;

pub use base64url::Base64urlError;
pub use key::{
    Algorithm, DEFAULT_ALLOWED_ALGORITHMS, EcCurve, JwkError, KEY_REFERENCE_MEMBERS, KID_MAX_BYTES,
    Kid, OkpCurve, PRIVATE_MEMBERS, PublicJwk, PublicKey, RSA_MAX_EXPONENT_OCTETS,
    RSA_MAX_MODULUS_BITS, RSA_MIN_EXPONENT, RSA_MIN_MODULUS_BITS,
};
pub use overlap::{KeysetVersion, LiveKey, OverlapError, VersionStatus, live_keys};
pub use set::{JwkSet, JwkSetError, MAX_KEYS, MAX_SET_BYTES, parse_jwk_set};
pub use thumbprint::Thumbprint;
