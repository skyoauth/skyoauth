//! [`sign_challenge`], which signs a checked challenge with a
//! [`RecoverySigner`], and [`verify_response`], which checks a signature as
//! the service checks it.
//!
//! The private key stays behind [`RecoverySigner`]: [`sign_challenge`] sees
//! only the signer's public key and the 64 bytes it returns, so a signer
//! backed by a device or an OS key store can take the place of
//! [`SoftwareSigner`] without a change here.
//!
//! A signer signs only a [`SigningRequest`], which [`sign_challenge`] alone
//! makes, after its checks. So no caller can have a signer of this crate
//! sign other bytes, and the gates of [`sign_challenge`] (a confirmed
//! replacement, a new key that is not the signer's) hold for every
//! signature a [`SoftwareSigner`] makes.

use std::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use zeroize::{Zeroize as _, ZeroizeOnDrop};

use super::{Challenge, KeyError, RecoveryPublicKey, SIGNATURE_LENGTH, VerifiedChallenge};

/// What [`sign_challenge`] asks a [`RecoverySigner`] to sign: `M` of a
/// challenge that passed every check of [`sign_challenge`].
///
/// Only [`sign_challenge`] makes one: it has no public constructor and no
/// `Clone`, `Copy` or `Default`, so a signer is never asked to sign bytes
/// that did not pass those checks. A signer may pass the request it was
/// given on, to a signer it wraps.
///
/// `Debug` prints `SigningRequest(..)`.
pub struct SigningRequest<'a> {
    message: &'a [u8],
}

impl fmt::Debug for SigningRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningRequest(..)")
    }
}

impl<'a> SigningRequest<'a> {
    /// The bytes to sign: `M`, the challenge exactly as the service issued
    /// it.
    pub const fn message(&self) -> &'a [u8] {
        self.message
    }
}

/// Signs the bytes of a recovery challenge with the recovery private key,
/// wherever that key is kept.
///
/// [`sign_challenge`] calls [`RecoverySigner::public_key`] once, then
/// [`RecoverySigner::sign`] once with a [`SigningRequest`] for `M`, and
/// checks the signature it gets with that public key before it returns it:
/// a signer whose key or output is wrong is refused, never passed on.
///
/// A signer of another crate can implement this trait; it is asked to sign
/// only through [`sign_challenge`], since nothing else can make a
/// [`SigningRequest`].
///
/// # Which key
///
/// The offline self-check of [`sign_challenge`] establishes only that the
/// signature is consistent with the key the signer reports: it cannot tell
/// the enrolled recovery key from another one. Choosing the signer that
/// holds the enrolled key is the caller's job. A signer holding a retired
/// key still passes the self-check against its own reported public key;
/// the service then refuses the signature against the enrolled key
/// (`NotRestorable(BadSignature)`).
pub trait RecoverySigner {
    /// The signer's recovery public key. A [`RecoveryPublicKey`] passed the
    /// service's key checks when it was made, so a signer cannot present a
    /// small-order, non-canonically encoded or undecodable key.
    fn public_key(&self) -> RecoveryPublicKey;

    /// The pure Ed25519 signature (RFC 8032) of
    /// [`SigningRequest::message`], 64 bytes.
    ///
    /// # Errors
    ///
    /// [`SignerError`] when the signer does not sign.
    fn sign(&self, request: &SigningRequest<'_>) -> Result<[u8; SIGNATURE_LENGTH], SignerError>;
}

/// Why a [`RecoverySigner`] did not sign. Carries nothing from the signer:
/// `Debug` names the variant only, `Display` is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer did not produce a signature: its key store or device is
    /// not available, or it refused.
    Failed,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Failed => "the recovery signer did not sign",
        })
    }
}

impl std::error::Error for SignerError {}

/// A [`RecoverySigner`] over an Ed25519 seed held in memory: for tests and
/// for a workstation that keeps the seed itself.
///
/// # The seed
///
/// Nothing in this crate writes the seed anywhere or shows it: the signer
/// has no `Clone`, `Copy`, `Display`, `Default`, `Deref` or `AsRef`, no
/// serialization and no method that returns the seed or the signing key,
/// and its `Debug` prints `SoftwareSigner(..)`. It signs only a
/// [`SigningRequest`], so only through [`sign_challenge`] and its checks.
///
/// It is wiped from memory, with `zeroize`'s writes (volatile, and kept
/// in order by a compiler fence, so the compiler does not drop them as
/// dead stores):
///
/// - [`SoftwareSigner::from_seed`] borrows the caller's seed mutably and
///   wipes it, in place, as soon as the signing key is made from it,
///   before it checks the public key, so on every return: no copy of the
///   seed is made by value, and the caller sees an all-zero array after;
/// - the signing key that holds the seed is wiped when the signer is
///   dropped: the crate builds `ed25519-dalek` with its `zeroize` feature,
///   whose `SigningKey` wipes its secret half on drop, as it wipes the
///   `ExpandedSecretKey` (the clamped scalar and the hash prefix) it
///   derives for the public key and for each signature. Without that
///   feature the crate does not build: a compile-time check requires
///   `SigningKey` to be wiped on drop.
///
/// What is not wiped here:
///
/// - other copies of the seed the caller made before it called
///   [`SoftwareSigner::from_seed`];
/// - a bitwise copy the compiler leaves when it moves the signer (or the
///   `Result` that carries it): a move does not wipe its old place, and
///   Rust gives no way to control it;
/// - the intermediate values of `ed25519-dalek` 3.0.0 and `sha2`:
///   `ExpandedSecretKey::from` (run by `SigningKey::from_bytes` and by
///   each signature) leaves on the stack, unwiped, the 64-byte SHA-512
///   digest of the seed, which is the expanded key itself, and the
///   `scalar_bytes` copy of its first half; the SHA-512 state over the
///   seed is not wiped either; nor are registers and spilled
///   temporaries;
/// - any copy outside the process's control, such as swap, a core dump or
///   a hibernation image.
///
/// The wipe is a best effort that shortens the seed's life in memory, not
/// a guarantee that no copy remains.
///
/// Signing is deterministic (RFC 8032): no random source is used.
pub struct SoftwareSigner {
    signing_key: SigningKey,
    public_key: RecoveryPublicKey,
}

/// Compiles only for a type that is wiped on drop.
const fn assert_wiped_on_drop<T: ZeroizeOnDrop>() {}

// The signing key is wiped on drop (`ed25519-dalek`'s `zeroize` feature),
// or the crate does not build.
const _: () = assert_wiped_on_drop::<SigningKey>();

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareSigner(..)")
    }
}

impl SoftwareSigner {
    /// The signer of the 32-byte Ed25519 seed `seed` (the RFC 8032 private
    /// key).
    ///
    /// The seed is borrowed mutably and wiped in place, all zeros, once
    /// the signing key is made from it, before any other step, on every
    /// return, an error included. Another copy the caller made is the
    /// caller's to wipe (see [`SoftwareSigner`], "The seed").
    ///
    /// # Errors
    ///
    /// The [`KeyError`] of [`RecoveryPublicKey::from_bytes`] for the seed's
    /// public key. The public key of a seed is a canonically encoded point
    /// of large order, so this is not expected to happen; the key is
    /// checked as the service checks a recovery key all the same, rather
    /// than assumed to pass.
    pub fn from_seed(seed: &mut [u8; 32]) -> Result<Self, KeyError> {
        let signing_key = SigningKey::from_bytes(seed);
        // The signing key holds its own copy, wiped on drop: the caller's
        // is wiped now.
        seed.zeroize();
        let public_key = RecoveryPublicKey::from_bytes(signing_key.verifying_key().as_bytes())?;
        Ok(Self {
            signing_key,
            public_key,
        })
    }
}

impl RecoverySigner for SoftwareSigner {
    fn public_key(&self) -> RecoveryPublicKey {
        self.public_key
    }

    fn sign(&self, request: &SigningRequest<'_>) -> Result<[u8; SIGNATURE_LENGTH], SignerError> {
        self.signing_key
            .try_sign(request.message())
            .map(|signature| signature.to_bytes())
            .map_err(|_| SignerError::Failed)
    }
}

/// Why [`sign_challenge`] did not sign. Carries no value of the challenge,
/// the key or the signature: `Debug` names the reason only, `Display` is
/// fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// [`check_challenge`](super::check_challenge) was not given all of
    /// the replacement's public identity, its trust anchor and the new
    /// recovery public key to compare with the plan (see
    /// [`VerifiedChallenge::replacement_confirmed`]).
    ReplacementNotConfirmed,
    /// The plan's new recovery public key is the signer's own key. The
    /// used key must be retired, so the service refuses such a plan at the
    /// issue (`NotIssuable`) and at the restore (`RecoveryKeyUnchanged`).
    RecoveryKeyUnchanged,
    /// The signer did not sign.
    Signer(SignerError),
    /// The signer's signature does not verify, strictly, with the signer's
    /// public key over `M`: a wrong key, a wrong message or a malformed
    /// signature. It is not returned.
    NotVerified,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReplacementNotConfirmed => {
                "the replacement's public identity, trust anchor and new recovery public key were \
                 not all confirmed"
            }
            Self::RecoveryKeyUnchanged => {
                "the challenge's new recovery public key is the signer's own key"
            }
            Self::Signer(_) => "the recovery signer did not sign",
            Self::NotVerified => {
                "the signer's signature does not verify with its public key over the challenge"
            }
        })
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signer(err) => Some(err),
            _ => None,
        }
    }
}

/// Why [`verify_response`] refused a signature. Carries no value: `Debug`
/// names the reason only, `Display` is fixed text. The service refuses both
/// with `NotRestorable(BadSignature)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature is not [`SIGNATURE_LENGTH`] bytes.
    Length,
    /// The signature does not verify with the key over `M`, as
    /// `ed25519-dalek`'s `verify_strict` checks it.
    NotVerified,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "the signature is not 64 bytes",
            Self::NotVerified => {
                "the signature does not verify with the recovery public key over the challenge"
            }
        })
    }
}

impl std::error::Error for VerifyError {}

/// The workstation's answer to a challenge: the challenge's operation ID
/// and the signature over its `M`, what the deployment operator hands to
/// the service's preview and restore.
///
/// A signature is not secret, but it authorizes the replacement the plan
/// names until the challenge expires, so `Debug` prints `SignedResponse(..)`,
/// none of the values, like the service's `SignedRecoveryResponse`.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedResponse {
    operation_id: String,
    signature: [u8; SIGNATURE_LENGTH],
}

impl fmt::Debug for SignedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedResponse(..)")
    }
}

impl SignedResponse {
    /// The operation ID of the challenge, `C`'s `id`.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// The Ed25519 signature over the challenge's `M`.
    pub const fn signature(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.signature
    }
}

/// Signs a checked challenge, in this order:
///
/// 1. the challenge's replacement was confirmed:
///    [`check_challenge`](super::check_challenge) compared the
///    replacement's public identity, its trust anchor and the new recovery
///    public key with what the operator approves
///    ([`VerifiedChallenge::replacement_confirmed`]);
/// 2. the plan's new recovery public key is not the signer's
///    ([`RecoverySigner::public_key`], called once): the service would
///    refuse it;
/// 3. the signer signs `M`, the challenge's bytes exactly as received, not
///    its hash and not `C`, as a [`SigningRequest`]: the one way any
///    signer is asked to sign, so steps 1 and 2 hold for every signature;
/// 4. the signature verifies with the signer's public key over `M` as the
///    service verifies it ([`verify_response`]: `verify_strict`), so a
///    signer that returns another key's signature, a signature over other
///    bytes or a malformed one is refused here and nothing is returned.
///
/// The self-check of step 4 establishes consistency with the key the
/// signer reports, not that this key is the enrolled recovery key: the
/// caller selects the signer of the enrolled key. A retired key's
/// signature still verifies against that key's own reported public key
/// here, and the service refuses it against the enrolled one
/// (`NotRestorable(BadSignature)`).
///
/// # Errors
///
/// The [`SignError`] of the first step that fails.
pub fn sign_challenge(
    challenge: &VerifiedChallenge<'_>,
    signer: &dyn RecoverySigner,
) -> Result<SignedResponse, SignError> {
    if !challenge.replacement_confirmed() {
        return Err(SignError::ReplacementNotConfirmed);
    }
    let checked = challenge.challenge();
    let public_key = signer.public_key();
    if public_key == checked.plan().new_recovery_public_key {
        return Err(SignError::RecoveryKeyUnchanged);
    }
    let request = SigningRequest {
        message: checked.message(),
    };
    let signature = signer.sign(&request).map_err(SignError::Signer)?;
    verify_message(&public_key, checked.message(), &signature)
        .map_err(|_| SignError::NotVerified)?;
    Ok(SignedResponse {
        operation_id: checked.operation_id().to_owned(),
        signature,
    })
}

/// Checks `signature` over the challenge's `M` with the recovery public key
/// `key` as the service's restore checks it: 64 bytes, then
/// `ed25519-dalek`'s `verify_strict`, which refuses an `S` not below the
/// group order, a non-canonical `R` and a small-order `R` (a small-order
/// key cannot be a [`RecoveryPublicKey`]).
///
/// # Errors
///
/// [`VerifyError::Length`] for a signature that is not 64 bytes, then
/// [`VerifyError::NotVerified`].
pub fn verify_response(
    key: &RecoveryPublicKey,
    challenge: &Challenge,
    signature: &[u8],
) -> Result<(), VerifyError> {
    let signature: &[u8; SIGNATURE_LENGTH] =
        signature.try_into().map_err(|_| VerifyError::Length)?;
    verify_message(key, challenge.message(), signature)
}

/// `verify_strict` of `signature` over `message` with `key`.
fn verify_message(
    key: &RecoveryPublicKey,
    message: &[u8],
    signature: &[u8; SIGNATURE_LENGTH],
) -> Result<(), VerifyError> {
    // A `RecoveryPublicKey` always decodes; a failure is refused all the
    // same.
    let key = VerifyingKey::from_bytes(key.as_bytes()).map_err(|_| VerifyError::NotVerified)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| VerifyError::NotVerified)
}
