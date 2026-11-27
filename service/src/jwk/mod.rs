//! Validation of uploaded public JWK Sets for `uploaded_jwks` trust sources
//! (T11.3): public-only keys, algorithms, strength and size, RFC 7638
//! thumbprints, explicit overlap and unique, nonconflicting `kid`s across
//! keyset versions.
//!
//! This module is pure: no I/O, no clock (time is a parameter) and no
//! dependency on the registry. `persistence::registry` may depend on it,
//! never the reverse (as for `policy`, lead ruling, 2026-11-21). Its one
//! caller is the keyset version write path [`crate::trust::keyset`],
//! itself wired to no endpoint yet (see "Follow-ups").
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
//! Every pick below is a lead decision dated 2026-11-21, except the
//! dependency choice of the point checks, which the user ruled on (see
//! below). A pick no source states is marked "(inferred)". The maintainer
//! ratified the ADRs directionally on 2026-11-24 and Gate M0 passed in
//! #140: the lead decisions stay implementation choices that ordinary
//! review can change, and a change to the user's ruling goes back to the
//! user.
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
//!   curve are refused (inferred). The point is then checked: `x` and `y`
//!   below the field prime `p` ([`JwkError::CoordinateOutOfRange`]) and
//!   `y^2 = x^3 - 3x + b (mod p)` ([`JwkError::PointNotOnCurve`]), the
//!   public-key validation of NIST SP 800-56A section 5.6.2.3 (umbrella
//!   section; the subsection numbering varies by revision; these curves
//!   have cofactor 1);
//! - `OKP`: `crv` `Ed25519` with `x` exactly 32 octets; `Ed448`, `X25519`,
//!   `X448` and every other curve are refused (inferred). The key is then
//!   decoded as in RFC 8032 section 5.1.3 (from memory, unverified), which
//!   refuses `y >= p = 2^255 - 19` and, when `x` is 0, the sign bit set
//!   ([`JwkError::Ed25519NotCanonical`]) and a `y` that does not decode to
//!   a point ([`JwkError::PointNotOnCurve`]); the eight points of order
//!   dividing 8 are refused in addition ([`JwkError::Ed25519SmallOrder`],
//!   provisional lead pick, 2026-11-21). A
//!   point with a torsion component (a prime-order point plus a
//!   small-order one) is accepted and not claimed safe: cofactor handling
//!   belongs to the verifier (T11.7, strict verification). This is not a
//!   full strict-verification validation;
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
//! The point checks (the `point` submodule) use hand-written modular
//! arithmetic on public data, not constant-time, with no new dependency
//! (provisional lead pick, 2026-11-21: an elliptic-curve crate would add 8
//! to 12 locked packages, a maintainer decision). Ruled by the user,
//! 2026-11-22, relayed by the lead: the hand-written arithmetic stays, and
//! no elliptic-curve crate is added. Their constants are
//! written as remembered from FIPS 186-4, SEC 2 and RFC 8032, not checked
//! against those documents; what was checked, by a Python recomputation,
//! is listed in the `point` submodule: the formulas, OpenSSL's generator
//! and generated keys on the curve, the SEED relation and RFC 8032's
//! decimal `d`.
//!
//! # Projection, fingerprint and stored sets
//!
//! - [`validate_keyset`] runs [`parse_jwk_set`] and returns a
//!   [`ValidatedKeyset`]: the set, its canonical public projection
//!   ([`ValidatedKeyset::public_json`], also [`JwkSet::to_public_json`])
//!   and its [`KeysetFingerprint`]. The projection is what the write path
//!   stores, never the raw upload (inferred): only `alg` (when uploaded),
//!   `kty`, `kid` and the key members ([`RSA_MEMBERS`], [`EC_MEMBERS`] or
//!   [`OKP_MEMBERS`]); members sorted (lexicographic, as RFC 7638 orders
//!   its input), keys sorted by `kid` (byte order), no whitespace. So the
//!   same keys uploaded in any order give the same bytes and fingerprint,
//!   and every set this module returns ([`JwkSet`], [`ValidatedKeyset`],
//!   [`StoredKeyset`]) lists its keys in that order (provisional lead pick,
//!   2026-11-22). `use`, `key_ops`, `x5t` and `x5t#S256` are dropped
//!   (inferred: `use` and `key_ops` can only be `sig` and `["verify"]`, the
//!   certificate thumbprints are unused), so a private member can never
//!   reach it. A projection is itself an accepted upload.
//! - The fingerprint (inferred) is the unpadded base64url of the SHA-256
//!   digest of the projection's bytes. Its use is open: the design section
//!   5.7 export gives a version only `id` and `public_jwks_ref` (OQ-IR-6),
//!   and what the version's `fingerprint` column holds is the wiring's
//!   decision (T11.9).
//! - [`parse_stored`] parses a version's `public_jwks` read back from the
//!   database, as text or bytes, into a [`StoredKeyset`]: every rule above
//!   (shape, size, allowlist, `alg` rules, lengths, unique `kid`s and keys)
//!   but no point arithmetic (provisional lead pick, 2026-11-22), with
//!   [`KNOWN_ALGORITHMS`] as the allowed set (inferred), after refusing
//!   input longer than [`MAX_STORED_BYTES`] (4 × [`MAX_SET_BYTES`]) before
//!   the raw parse (provisional lead pick, 2026-11-22). It recomputes the
//!   projection and fingerprint, which do not depend on how `jsonb` orders
//!   or spaces the text. The stored value is trusted to have been validated
//!   at write; the `0004` `CHECK` floor does not make that true by itself.
//!   Its keys are not verifier-ready, since no point checks ran
//!   (provisional lead pick, 2026-11-22): the verifier (T11.7) builds its
//!   keys from a full [`validate_keyset`] pass instead. Its errors are data-integrity errors (a stored row that
//!   breaks the rules), not client errors: a future HTTP mapping must not
//!   reuse the upload mapping of [`JwkSetError`].
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
//! `Debug` by hand and print no key octets either; nor do
//! [`ValidatedKeyset`] and [`StoredKeyset`], whose `Debug` leaves out the
//! projection. [`JwkSetError::NotJson`] drops the JSON parser's message.
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
//! this module's output. Further EC and Ed25519 keys were generated with
//! `cryptography`, and every point vector, valid or not, was classified in
//! Python (integer arithmetic, and OpenSSL through `cryptography` for the
//! valid NIST points). See `service/tests/jwk.rs`.
//!
//! # Follow-ups
//!
//! - **Points.** The former gate is met: EC points are checked on-curve
//!   with `x`, `y` < p, and Ed25519 keys canonical (y < p, no negative
//!   zero) and not small-order. T11.7 must still use strict Ed25519
//!   verification (a key with a torsion component passes this module), and
//!   T24.3's "fake keys" negative stays the acceptance test. Validation is
//!   CPU-bound (about 8.8 ms per Ed25519 key in release, about 0.18 s per
//!   20-key set): the wiring PR must run it on bounded blocking workers
//!   (`spawn_blocking` with a limit), and T11.7 must build its key cache
//!   once per version (see below), not re-parse per request. An
//!   optimisation of the `x^2` computation (as `u * v`) is deferred.
//! - The wiring PR must bound the raw request body before parsing it: this
//!   module bounds only the parsed value.
//! - The allowed algorithm set (OQ-TP-3, open) and its intersection with a
//!   source's `algorithms` allowlist.
//! - Wiring into the trust keyset write path (T11.9, T24.2): calling
//!   [`validate_keyset`] at write and storing its
//!   [`ValidatedKeyset::public_json`], never the raw upload. The registry
//!   write API must take a `&ValidatedKeyset`, never a `&StoredKeyset` or
//!   a bare `&str`: [`StoredKeyset::public_json`] returns the same `&str`,
//!   so a copy or restore path could otherwise store keys whose points were
//!   never checked. Also calling
//!   [`check_version_overlap`] wherever a version becomes enabled
//!   (creation as enabled, re-enable, import, restore), serializing the
//!   writes of one keyset (lock the parent keyset row or advance its
//!   revision), and deciding what the version's `fingerprint` column holds:
//!   this module offers [`KeysetFingerprint`] (inferred), whose use is open
//!   (OQ-IR-6). [`crate::trust::keyset`] now does this: it takes a
//!   `&ValidatedKeyset`, stores the projection and the [`KeysetFingerprint`]
//!   (provisional lead pick, 2026-11-22), runs [`check_version_overlap`] at
//!   an enabled create and an enable, and locks the parent keyset row.
//! - One write path (provisional lead pick, 2026-11-22). The raw registry
//!   writer `persistence::registry::create_trust_keyset_version` stores
//!   whatever `public_jwks` and `fingerprint` it is given, unchecked.
//!   [`crate::trust::keyset`] must be the only write path; the raw writer
//!   is crate-private (second-approver proposal, PR 9): only that module
//!   calls it in the crate, tests reach it through the `test-support`
//!   feature, and it stays unreachable from any endpoint.
//! - The verifier's keys (T11.7; provisional lead pick, 2026-11-22). The
//!   verifier's key cache is built from a full
//!   `validate_keyset(&stored, &KNOWN_ALGORITHMS)` pass per version (on
//!   bounded blocking workers, see "Points"), never from [`parse_stored`],
//!   whose keys are not verifier-ready. A row written
//!   before the write wiring existed, or an imported row, gets that full
//!   pass too. A separate verifier type (for example `VerifierKeys`) built
//!   only by the full pass stays an option for later.
//! - The overlap input gap hits the registry write path first, before
//!   T11.7: [`check_version_overlap`] needs the other enabled versions,
//!   read back from the database, as [`JwkSet`]s, which only the full parse
//!   builds. The write path ([`crate::trust::keyset`]) now parses them again
//!   in full, inside its transaction (about 0.18 s per 20-key set, see
//!   "Points"; provisional lead pick, 2026-11-22); a change of
//!   [`KeysetVersion`] to take [`StoredKeyset`] keys would remove that cost
//!   (open). [`live_keys`] at verification (T11.7) takes the sets of the
//!   verifier's full pass, so it has no such gap.
//! - Whether validity windows should stay immutable, so that an operator
//!   could close an open-ended window instead of disabling the version
//!   (open question).
//! - Selecting the live verification key of the explicitly selected source
//!   (T11.7) from [`live_keys`].

pub(crate) mod base64url;
mod key;
mod overlap;
pub(crate) mod point;
mod projection;
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
pub use projection::{
    KeysetFingerprint, MAX_STORED_BYTES, StoredKeyset, ValidatedKeyset, parse_stored,
    validate_keyset,
};
pub use set::{JwkSet, JwkSetError, MAX_KEYS, MAX_SET_BYTES, parse_jwk_set};
pub use thumbprint::Thumbprint;
