//! The live keys of a keyset across its versions: explicit overlap and
//! unique, nonconflicting live `kid`s (ADR-005 item 2; design section 5.4:
//! "Multiple versions may be active; conflicting live kid/key combinations
//! deny").

use std::{collections::BTreeMap, fmt, time::SystemTime};

use super::key::{Kid, PublicJwk};
use super::set::JwkSet;
use super::thumbprint::Thumbprint;

/// A keyset version's `status`, mirrored here so this module does not
/// depend on the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    Enabled,
    Disabled,
}

/// One keyset version as the overlap check needs it. Times follow the
/// registry's `SystemTime` convention.
#[derive(Debug, Clone, Copy)]
pub struct KeysetVersion<'a> {
    /// The version's ID, used only to name it in errors and results.
    pub id: &'a str,
    pub effective_at: SystemTime,
    /// `None` for no expiry.
    pub expires_at: Option<SystemTime>,
    pub status: VersionStatus,
    pub keys: &'a JwkSet,
}

impl KeysetVersion<'_> {
    /// Whether the version is live at `at`: enabled and
    /// `effective_at <= at < expires_at`, the start inclusive and the
    /// expiry exclusive (inferred).
    pub fn is_live(&self, at: SystemTime) -> bool {
        self.status == VersionStatus::Enabled
            && self.effective_at <= at
            && self.expires_at.is_none_or(|expires_at| at < expires_at)
    }
}

/// One live key and the live versions that carry it, in input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveKey<'a> {
    pub key: &'a PublicJwk,
    pub version_ids: Vec<&'a str>,
}

/// A conflict between two live versions. `first_version` is the earlier
/// of the two in the input order. No variant holds key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlapError {
    /// One `kid` names two different keys (different thumbprints).
    KidConflict {
        kid: Kid,
        first_version: String,
        second_version: String,
    },
    /// One key (same thumbprint) has two different `kid`s.
    KeyConflict {
        first_kid: Kid,
        second_kid: Kid,
        first_version: String,
        second_version: String,
    },
    /// One `kid` and key carry different `alg` members, an absent `alg`
    /// counting as different from a present one (inferred: a conflict,
    /// since the merged key would have no single `alg`).
    AlgorithmConflict {
        kid: Kid,
        first_version: String,
        second_version: String,
    },
}

impl fmt::Display for OverlapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KidConflict {
                kid,
                first_version,
                second_version,
            } => write!(
                f,
                "live versions \"{first_version}\" and \"{second_version}\" give kid \"{kid}\" different keys"
            ),
            Self::KeyConflict {
                first_kid,
                second_kid,
                first_version,
                second_version,
            } => write!(
                f,
                "live versions \"{first_version}\" and \"{second_version}\" give one key the kids \"{first_kid}\" and \"{second_kid}\""
            ),
            Self::AlgorithmConflict {
                kid,
                first_version,
                second_version,
            } => write!(
                f,
                "live versions \"{first_version}\" and \"{second_version}\" give kid \"{kid}\" different alg members"
            ),
        }
    }
}

impl std::error::Error for OverlapError {}

/// The merged live keys of `versions` at `at`, sorted by `kid`
/// byte-wise, or the first conflict found (see [`OverlapError`]). A key
/// with the same `kid`, thumbprint and `alg` in several live versions is
/// one entry (explicit overlap). Versions that are not live at `at` (see
/// [`KeysetVersion::is_live`]) are ignored entirely.
pub fn live_keys<'a>(
    versions: &[KeysetVersion<'a>],
    at: SystemTime,
) -> Result<Vec<LiveKey<'a>>, OverlapError> {
    let mut by_kid: BTreeMap<&'a Kid, LiveKey<'a>> = BTreeMap::new();
    let mut by_thumbprint: BTreeMap<&'a Thumbprint, &'a Kid> = BTreeMap::new();
    for version in versions.iter().filter(|version| version.is_live(at)) {
        for key in version.keys.keys() {
            if let Some(live) = by_kid.get_mut(key.kid()) {
                let first_version = live.version_ids[0].to_owned();
                if live.key.thumbprint() != key.thumbprint() {
                    return Err(OverlapError::KidConflict {
                        kid: key.kid().clone(),
                        first_version,
                        second_version: version.id.to_owned(),
                    });
                }
                if live.key.alg() != key.alg() {
                    return Err(OverlapError::AlgorithmConflict {
                        kid: key.kid().clone(),
                        first_version,
                        second_version: version.id.to_owned(),
                    });
                }
                live.version_ids.push(version.id);
                continue;
            }
            if let Some(&other_kid) = by_thumbprint.get(key.thumbprint()) {
                return Err(OverlapError::KeyConflict {
                    first_kid: other_kid.clone(),
                    second_kid: key.kid().clone(),
                    first_version: by_kid[other_kid].version_ids[0].to_owned(),
                    second_version: version.id.to_owned(),
                });
            }
            by_thumbprint.insert(key.thumbprint(), key.kid());
            by_kid.insert(
                key.kid(),
                LiveKey {
                    key,
                    version_ids: vec![version.id],
                },
            );
        }
    }
    Ok(by_kid.into_values().collect())
}
