//! The keys of a keyset across its versions: explicit overlap and unique,
//! nonconflicting live `kid`s (ADR-005 items 1 and 5; design section 5.4:
//! "Multiple versions may be active; conflicting live kid/key combinations
//! deny").
//!
//! Two checks use the same three rules (a `kid` with two keys, a key with
//! two `kid`s, a `kid` and key with two algorithms, see
//! [`PublicJwk::algorithm`]): [`check_version_overlap`] whenever a version
//! becomes enabled, over the other enabled versions whose windows
//! intersect; and [`live_keys`] at verification time, over the versions
//! live at one instant, the runtime backstop.
//!
//! # Rotation (inferred)
//!
//! Validity windows are immutable in the registry (a version's `status` is
//! its one mutable column), so disabling is the only way to retire a
//! version, an open-ended one included. To replace the key of a `kid`:
//! disable the old version, then write the replacement, enabled, with the
//! same `kid`; the check skips disabled versions, so it passes. While the
//! replacement is enabled, re-enabling the old version is refused; once
//! the replacement is disabled, it is accepted again. A replacement created
//! disabled can be enabled only once the old version is disabled. Whether
//! validity windows should stay immutable, so that an operator could
//! instead close an open-ended window, is an open question (module
//! follow-ups).

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
    /// expiry exclusive (inferred). A window whose expiry is not after its
    /// start is empty: such a version is never live.
    pub fn is_live(&self, at: SystemTime) -> bool {
        self.status == VersionStatus::Enabled
            && self.effective_at <= at
            && self.expires_at.is_none_or(|expires_at| at < expires_at)
    }

    /// Whether the validity windows `[effective_at, expires_at)` of `self`
    /// and `other` share an instant, whatever the statuses: `a.start <
    /// b.end && b.start < a.end`, no expiry meaning no end. An empty
    /// window (expiry not after start) intersects nothing (inferred).
    pub fn windows_intersect(&self, other: &KeysetVersion<'_>) -> bool {
        let nonempty = |v: &KeysetVersion<'_>| v.expires_at.is_none_or(|end| v.effective_at < end);
        nonempty(self)
            && nonempty(other)
            && other.expires_at.is_none_or(|end| self.effective_at < end)
            && self.expires_at.is_none_or(|end| other.effective_at < end)
    }
}

/// One live key and the live versions that carry it, in input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveKey<'a> {
    pub key: &'a PublicJwk,
    pub version_ids: Vec<&'a str>,
}

/// A conflict between two versions. From [`live_keys`], `first_version`
/// is the earlier of the two in the input order; from
/// [`check_version_overlap`], it is the existing version and
/// `second_version` the one checked. No variant holds key material.
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
    /// One `kid` and key resolve to different algorithms
    /// ([`PublicJwk::algorithm`]: the `alg` member, or the curve's one
    /// algorithm for a key without one; inferred: a conflict, since the
    /// merged key would have no single algorithm).
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
                "versions \"{first_version}\" and \"{second_version}\" give kid \"{kid}\" different keys"
            ),
            Self::KeyConflict {
                first_kid,
                second_kid,
                first_version,
                second_version,
            } => write!(
                f,
                "versions \"{first_version}\" and \"{second_version}\" give one key the kids \"{first_kid}\" and \"{second_kid}\""
            ),
            Self::AlgorithmConflict {
                kid,
                first_version,
                second_version,
            } => write!(
                f,
                "versions \"{first_version}\" and \"{second_version}\" give kid \"{kid}\" different algorithms"
            ),
        }
    }
}

impl std::error::Error for OverlapError {}

/// The merged live keys of `versions` at `at`, sorted by `kid`
/// byte-wise, or the first conflict found (see [`OverlapError`]). A key
/// with the same `kid`, thumbprint and resolved algorithm in several live
/// versions is
/// one entry (explicit overlap). Versions that are not live at `at` (see
/// [`KeysetVersion::is_live`]) are ignored entirely. One conflict denies
/// the whole live set, not only the conflicting `kid` (inferred).
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
                if live.key.algorithm() != key.algorithm() {
                    return Err(OverlapError::AlgorithmConflict {
                        kid: key.kid().clone(),
                        first_version,
                        second_version: version.id.to_owned(),
                    });
                }
                // The same version given twice is listed once.
                if !live.version_ids.contains(&version.id) {
                    live.version_ids.push(version.id);
                }
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

/// Checks a version that is becoming enabled against the other versions of
/// its keyset (inferred). The caller runs it at every point where a
/// version becomes enabled: creation as enabled, re-enable, and any import
/// or restore path; creating a disabled version may skip it. For a
/// re-enable, pass the re-enabled version as `version` and the keyset's
/// versions as `existing`; `version`'s own status is not read.
///
/// The function filters `existing` itself: it skips disabled versions
/// (retired, see the module docs, "Rotation") and any version with
/// `version`'s ID, so `existing` may be the keyset's full list. `version`
/// is compared with every remaining version whose window intersects its
/// own (see [`KeysetVersion::windows_intersect`]), under the rules of
/// [`live_keys`]: a `kid` with a different key, a key under a different
/// `kid`, or a `kid` and key with a different [`PublicJwk::algorithm`] is a
/// conflict. Versions of `existing` are not compared with each other.
///
/// The check is only sound if the writes of one keyset are serialized (the
/// wiring locks the parent keyset row or advances its revision, T11.9,
/// T24.2); [`live_keys`] stays the runtime backstop.
pub fn check_version_overlap(
    version: &KeysetVersion<'_>,
    existing: &[KeysetVersion<'_>],
) -> Result<(), OverlapError> {
    let others = existing
        .iter()
        .filter(|other| other.status == VersionStatus::Enabled)
        .filter(|other| other.id != version.id);
    for other in others.filter(|other| version.windows_intersect(other)) {
        let versions = || (other.id.to_owned(), version.id.to_owned());
        for key in version.keys.keys() {
            for old in other.keys.keys() {
                let (first_version, second_version) = versions();
                if old.kid() == key.kid() {
                    if old.thumbprint() != key.thumbprint() {
                        return Err(OverlapError::KidConflict {
                            kid: key.kid().clone(),
                            first_version,
                            second_version,
                        });
                    }
                    if old.algorithm() != key.algorithm() {
                        return Err(OverlapError::AlgorithmConflict {
                            kid: key.kid().clone(),
                            first_version,
                            second_version,
                        });
                    }
                } else if old.thumbprint() == key.thumbprint() {
                    return Err(OverlapError::KeyConflict {
                        first_kid: old.kid().clone(),
                        second_kid: key.kid().clone(),
                        first_version,
                        second_version,
                    });
                }
            }
        }
    }
    Ok(())
}
