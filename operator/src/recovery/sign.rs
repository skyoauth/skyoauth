//! [`sign_challenge`], which signs a checked challenge with a
//! [`RecoverySigner`], and [`verify_response`], which checks a signature as
//! the service checks it.
//!
//! The private key stays behind [`RecoverySigner`]: [`sign_challenge`] sees
//! only the signer's public key and the 64 bytes it returns, so a signer
//! backed by a device or an OS key store can take the place of
//! [`SoftwareSigner`] without a change here.

use std::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use super::{Challenge, KeyError, RecoveryPublicKey, SIGNATURE_LENGTH, VerifiedChallenge};

/// Signs the bytes of a recovery challenge with the recovery private key,
/// wherever that key is kept.
///
/// [`sign_challenge`] calls [`RecoverySigner::public_key`] once, then
/// [`RecoverySigner::sign`] once with `M`, and checks the signature it gets
/// with that public key before it returns it: a signer whose key or output
/// is wrong is refused, never passed on.
pub trait RecoverySigner {
    /// The signer's recovery public key. A [`RecoveryPublicKey`] passed the
    /// service's key checks when it was made, so a signer cannot present a
    /// small-order, non-canonically encoded or undecodable key.
    fn public_key(&self) -> RecoveryPublicKey;

    /// The pure Ed25519 signature (RFC 8032) of `message`, 64 bytes.
    ///
    /// # Errors
    ///
    /// [`SignerError`] when the signer does not sign.
    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LENGTH], SignerError>;
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
/// and its `Debug` prints `SoftwareSigner(..)`.
///
/// It is **not** wiped from memory when the signer is dropped: the crate's
/// `ed25519-dalek` is built without its `zeroize` feature (the workspace
/// builds it with `default-features = false`), and the crate adds no
/// wiping of its own, which without that feature could not be relied on.
/// The copy of the seed that [`SoftwareSigner::from_seed`] takes by value
/// is the caller's to keep short-lived.
///
/// Signing is deterministic (RFC 8032): no random source is used.
pub struct SoftwareSigner {
    signing_key: SigningKey,
    public_key: RecoveryPublicKey,
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareSigner(..)")
    }
}

impl SoftwareSigner {
    /// The signer of the 32-byte Ed25519 seed `seed` (the RFC 8032 private
    /// key).
    ///
    /// # Errors
    ///
    /// The [`KeyError`] of [`RecoveryPublicKey::from_bytes`] for the seed's
    /// public key. The public key of a seed is a canonically encoded point
    /// of large order, so this is not expected to happen; the key is
    /// checked as the service checks a recovery key all the same, rather
    /// than assumed to pass.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, KeyError> {
        let signing_key = SigningKey::from_bytes(&seed);
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

    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LENGTH], SignerError> {
        self.signing_key
            .try_sign(message)
            .map(|signature| signature.to_bytes())
            .map_err(|_| SignerError::Failed)
    }
}

/// Why [`sign_challenge`] did not sign. Carries no value of the challenge,
/// the key or the signature: `Debug` names the reason only, `Display` is
/// fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// [`check_challenge`](super::check_challenge) was not given both the
    /// replacement's public identity and the new recovery public key to
    /// compare with the plan (see
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
                "the replacement's public identity and new recovery public key were not both \
                 confirmed"
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
///    [`check_challenge`](super::check_challenge) compared both the
///    replacement's public identity and the new recovery public key with
///    what the operator approves ([`VerifiedChallenge::replacement_confirmed`]);
/// 2. the plan's new recovery public key is not the signer's
///    ([`RecoverySigner::public_key`], called once): the service would
///    refuse it;
/// 3. the signer signs `M`, the challenge's bytes exactly as received, not
///    its hash and not `C`;
/// 4. the signature verifies with the signer's public key over `M` as the
///    service verifies it ([`verify_response`]: `verify_strict`), so a
///    signer that returns another key's signature, a signature over other
///    bytes or a malformed one is refused here and nothing is returned.
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
    let signature = signer.sign(checked.message()).map_err(SignError::Signer)?;
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
