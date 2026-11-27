//! Reconciling a write whose outcome is unknown with the transport's
//! `status` (see the [module documentation](super), "Reconciling"): the
//! `status` request of a restore or a bootstrap
//! ([`StatusRequest::reconciling_restore`],
//! [`StatusRequest::reconciling_bootstrap`]) and the verdict of its reply
//! ([`RestoreVerdict::of`], [`BootstrapVerdict::of`]), pure and built on
//! every platform; and, Unix only, the walk over the credentials a restore
//! revoked ([`LocalClient::revoked_credential_ids`]), the page iterator of
//! `docs/proposals/local-read-operation.md`.

use sha2::{Digest as _, Sha256};

use super::{
    BootstrapRequest, EnrolledState, OperationState, ResponseRequest, Status, StatusRequest,
};
#[cfg(unix)]
use super::{
    CallError, Connector, LocalClient, MAX_REVOKED_IDS_PER_REPLY, Restored, UnknownOutcome,
};

impl StatusRequest {
    /// The `status` request that reconciles `restore`: its operation ID
    /// alone (the original one, also after a repeated or a new restore).
    pub fn reconciling_restore(restore: &ResponseRequest) -> Self {
        Self {
            operation_id: Some(restore.operation_id.clone()),
            credential_spki: None,
            revoked_after: None,
        }
    }

    /// The `status` request that reconciles `bootstrap`: its mTLS key
    /// alone, the same DER bytes it sent (the public identity is per
    /// encoding).
    pub fn reconciling_bootstrap(bootstrap: &BootstrapRequest) -> Self {
        Self {
            operation_id: None,
            credential_spki: Some(bootstrap.credential_spki.clone()),
            revoked_after: None,
        }
    }
}

/// What a `status` reply says of a restore whose outcome is unknown, asked
/// with its operation ID ([`StatusRequest::reconciling_restore`]): the
/// restore procedure of the [module documentation](super), "Reconciling".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreVerdict {
    /// [`OperationState::Restored`]: it committed. The reply has the
    /// replacement's IDs; the revoked IDs page by `revoked_after`
    /// ([`LocalClient::revoked_credential_ids`] with no restore reply).
    Committed,
    /// [`OperationState::Retired`] or [`OperationState::Revoked`]: it did
    /// not commit and never will. Issue a new challenge.
    NeverCommits,
    /// [`OperationState::Issued`]: not committed yet. Repeat the same
    /// restore (single use): it restores, or is `not_restorable` because
    /// the first one committed; then reconcile again.
    RepeatRestore,
    /// [`OperationState::Expiring`]: a restore that read its time before
    /// the expiry may still be running. Ask again after `settles_at`, the
    /// time carried (whole microseconds since the Unix epoch, the
    /// transport's clock).
    AskAgainAfter(i64),
    /// [`OperationState::Expired`]: it did not commit through this
    /// transport. Issue a new challenge; not final (a writer with an
    /// earlier time may still consume it, and then the new challenge's
    /// restore is `not_restorable` and the old one shows
    /// [`OperationState::Restored`]).
    Expired,
    /// Anything else: no state reported, [`OperationState::NotFound`] (an
    /// operation ID the client holds came from a committed issue), or an
    /// `expiring` state without its `settles_at`. Do not proceed.
    Unknown,
}

impl RestoreVerdict {
    /// The verdict of `status`, the reply to
    /// [`StatusRequest::reconciling_restore`] of the original restore, by
    /// its operation state alone.
    pub const fn of(status: &Status) -> Self {
        match (status.operation_state, status.settles_at) {
            (Some(OperationState::Restored), _) => Self::Committed,
            (Some(OperationState::Retired | OperationState::Revoked), _) => Self::NeverCommits,
            (Some(OperationState::Issued), _) => Self::RepeatRestore,
            (Some(OperationState::Expiring), Some(settles_at)) => Self::AskAgainAfter(settles_at),
            (Some(OperationState::Expired), _) => Self::Expired,
            (Some(OperationState::NotFound | OperationState::Expiring) | None, _) => Self::Unknown,
        }
    }
}

/// What a `status` reply says of a bootstrap whose outcome is unknown,
/// asked with its mTLS key ([`StatusRequest::reconciling_bootstrap`]): the
/// bootstrap procedure of the [module documentation](super),
/// "Reconciling" (lead rulings, F4 and (b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BootstrapVerdict {
    /// The instance ID, the recovery public key, the mTLS key (enrolled,
    /// in any state) and the SHA-256 of the trust anchor reference all
    /// equal the request's: the current state matches it, consistent with
    /// it having committed. Do not repeat it. Which request won is not
    /// known, and the key may have been enrolled by a later write; the
    /// credential (`enrolled_admin_id`, `enrolled_credential_id`) is usable
    /// only when `enabled` is true ([`EnrolledState::Enabled`]).
    Matches {
        /// Whether the credential is enabled.
        enabled: bool,
    },
    /// No recovery state (`instance_id` is `null`): repeat the same
    /// bootstrap, which the database closes once.
    RepeatBootstrap,
    /// Anything else (another instance, another recovery key, the mTLS key
    /// not enrolled, another trust anchor): the current state does not
    /// match. Do not claim the bootstrap committed; stop. The historical
    /// outcome of the differing request is not reconstructible from the
    /// state.
    DoesNotMatch,
}

impl BootstrapVerdict {
    /// The verdict of `status`, the reply to
    /// [`StatusRequest::reconciling_bootstrap`] of `bootstrap`. The trust
    /// anchor reference is compared by the SHA-256 of the UTF-8 bytes of
    /// the value sent (the string, not its escaped wire form).
    pub fn of(bootstrap: &BootstrapRequest, status: &Status) -> Self {
        let Some(instance_id) = &status.instance_id else {
            return Self::RepeatBootstrap;
        };
        let anchor = Sha256::digest(bootstrap.trust_anchor_ref.as_bytes());
        let enrolled = match status.enrolled_state {
            Some(EnrolledState::Enabled) => Some(true),
            Some(EnrolledState::Disabled | EnrolledState::Revoked) => Some(false),
            Some(EnrolledState::NotFound) | None => None,
        };
        match enrolled {
            Some(enabled)
                if *instance_id == bootstrap.instance_id
                    && status.recovery_public_key.as_deref()
                        == Some(bootstrap.recovery_public_key.as_bytes().as_slice())
                    && status.enrolled_trust_anchor_sha256.as_deref()
                        == Some(anchor.as_slice()) =>
            {
                Self::Matches { enabled }
            }
            _ => Self::DoesNotMatch,
        }
    }
}

/// How one walk over the pages ended.
#[cfg(unix)]
enum Walk {
    /// Every ID of the count, in byte order.
    Done(Vec<String>),
    /// The documented tie: a `status` count above the restore reply's, or
    /// one that changed between `status` pages.
    Tie,
}

#[cfg(unix)]
impl<C: Connector> LocalClient<C> {
    /// Every credential the restore of `operation_id` revoked, in byte
    /// order: the page iterator. `restored` is that restore's reply, its
    /// count and first page; without it (a restore reconciled as
    /// [`RestoreVerdict::Committed`]) the walk starts from `status` alone.
    /// The rest is read with `status` calls of `operation_id`, each with
    /// `revoked_after` set to the last ID held, until the count is held.
    ///
    /// The codec checks each reply's shape and the order within it; the
    /// walk checks the rest (lead ruling (e)), exactly:
    ///
    /// - the first page (the restore reply's list, or the first `status`
    ///   page of a walk from `status` alone) has `min(count, page size)`
    ///   IDs, the page size [`MAX_REVOKED_IDS_PER_REPLY`], and the count is
    ///   not negative;
    /// - each later `status` reply is [`OperationState::Restored`] with a
    ///   count and a page, the page exactly `min(page size, count - held)`
    ///   IDs, each greater than the `revoked_after` sent;
    /// - the count is the same on every page of one walk.
    ///
    /// A `status` count above the restore reply's, or one that changes
    /// between `status` pages, is the documented tie (membership is by
    /// timestamp, so a revocation at the restore's own microsecond is
    /// listed too): the walk restarts from `status` alone, once. Anything
    /// else is an unknown outcome. The list then holds what the service
    /// selects at that time, the restore's credentials and maybe the
    /// tie's. A credential's `revoked_at` is set once and no credential is
    /// deleted, so a count never falls: the list returned holds at least
    /// the largest count seen in the walk (the restore reply's included),
    /// and every ID of the restore reply's list; a restarted walk that
    /// does not is an unknown outcome.
    ///
    /// # Errors
    ///
    /// - [`UnknownOutcome::PageMismatch`] when the pages do not hold
    ///   together as above, a second tie follows the restart, or the list
    ///   holds fewer IDs than the largest count seen or misses an ID of the
    ///   restore reply's list;
    /// - the error of a `status` call, as it is: `status` changes no row
    ///   and is [`Retry::Safe`](super::Retry::Safe), so the walk may be
    ///   run again. The restore's own outcome is the restore reply's, which
    ///   no error here changes.
    pub fn revoked_credential_ids(
        &self,
        operation_id: &str,
        restored: Option<&Restored>,
    ) -> Result<Vec<String>, CallError> {
        // The largest count seen so far: the list must hold at least as
        // many IDs.
        let mut largest = 0;
        let walk = match restored {
            Some(restored) => {
                let held = first_page(
                    restored.revoked_credential_count,
                    &restored.revoked_credential_ids,
                )?;
                largest = restored.revoked_credential_count;
                self.pages(
                    operation_id,
                    restored.revoked_credential_count,
                    held.to_vec(),
                    true,
                    &mut largest,
                )?
            }
            None => self.walk_from_status(operation_id, &mut largest)?,
        };
        // The one restart.
        let walk = match walk {
            Walk::Done(ids) => Walk::Done(ids),
            Walk::Tie => self.walk_from_status(operation_id, &mut largest)?,
        };
        let Walk::Done(ids) = walk else {
            return Err(mismatch());
        };
        let first = restored.map_or(&[][..], |restored| &restored.revoked_credential_ids);
        if usize::try_from(largest).is_ok_and(|largest| ids.len() >= largest)
            && first.iter().all(|id| ids.binary_search(id).is_ok())
        {
            Ok(ids)
        } else {
            Err(mismatch())
        }
    }

    /// A walk from `status` alone: its first page, then the rest.
    /// `largest` is raised to every count read.
    fn walk_from_status(&self, operation_id: &str, largest: &mut i64) -> Result<Walk, CallError> {
        let (count, page) = restored_page(self.status(&StatusRequest {
            operation_id: Some(operation_id.to_owned()),
            credential_spki: None,
            revoked_after: None,
        })?)?;
        *largest = (*largest).max(count);
        first_page(count, &page)?;
        self.pages(operation_id, count, page, false, largest)
    }

    /// The pages after `held`, the first page, until `count` IDs are held.
    /// `count` is the restore reply's when `after_restore`: a first
    /// `status` count above it is a tie, one below it a mismatch. Between
    /// `status` pages, any change of the count is a tie. A page with an ID
    /// not after the `revoked_after` sent is a mismatch, whatever its
    /// count. `largest` is raised to every count read.
    fn pages(
        &self,
        operation_id: &str,
        count: i64,
        mut held: Vec<String>,
        mut after_restore: bool,
        largest: &mut i64,
    ) -> Result<Walk, CallError> {
        let total = usize::try_from(count).map_err(|_| mismatch())?;
        while held.len() < total {
            // Not empty: the first page holds `min(count, page size)` IDs.
            let after = held.last().ok_or_else(mismatch)?.clone();
            let (page_count, page) = restored_page(self.status(&StatusRequest {
                operation_id: Some(operation_id.to_owned()),
                credential_spki: None,
                revoked_after: Some(after.clone()),
            })?)?;
            *largest = (*largest).max(page_count);
            if page.iter().any(|id| *id <= after) {
                return Err(mismatch());
            }
            if page_count != count {
                return if !after_restore || page_count > count {
                    Ok(Walk::Tie)
                } else {
                    Err(mismatch())
                };
            }
            after_restore = false;
            if page.len() != MAX_REVOKED_IDS_PER_REPLY.min(total - held.len()) {
                return Err(mismatch());
            }
            held.extend(page);
        }
        Ok(Walk::Done(held))
    }
}

/// The page `ids` of a first page, checked: `count` not negative and
/// `min(count, page size)` IDs.
#[cfg(unix)]
fn first_page(count: i64, ids: &[String]) -> Result<&[String], CallError> {
    let total = usize::try_from(count).map_err(|_| mismatch())?;
    if ids.len() == MAX_REVOKED_IDS_PER_REPLY.min(total) {
        Ok(ids)
    } else {
        Err(mismatch())
    }
}

/// The count and the page of a `status` reply of a restored challenge.
#[cfg(unix)]
fn restored_page(status: Status) -> Result<(i64, Vec<String>), CallError> {
    match status {
        Status {
            operation_state: Some(OperationState::Restored),
            revoked_credential_count: Some(count),
            revoked_credential_ids: Some(page),
            ..
        } => Ok((count, page)),
        _ => Err(mismatch()),
    }
}

#[cfg(unix)]
const fn mismatch() -> CallError {
    CallError::Unknown(UnknownOutcome::PageMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::RecoveryPublicKey;

    fn key(hex: &str) -> RecoveryPublicKey {
        RecoveryPublicKey::from_hex(hex).unwrap()
    }

    const KEY: &str = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a";
    const OTHER_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn bootstrap() -> BootstrapRequest {
        BootstrapRequest {
            instance_id: "instance".into(),
            credential_spki: vec![0xc7; 44],
            trust_anchor_ref: "anchor \u{e9}\n".into(),
            recovery_public_key: key(KEY),
        }
    }

    /// A `status` reply with every member `null` but `server_time`.
    fn empty() -> Status {
        Status {
            server_time: 1,
            instance_id: None,
            recovery_key_epoch: None,
            recovery_state_revision: None,
            recovery_public_key: None,
            operation_state: None,
            expires_at: None,
            settles_at: None,
            restored_at: None,
            admin_id: None,
            credential_id: None,
            binding_id: None,
            revoked_credential_count: None,
            revoked_credential_ids: None,
            enrolled_state: None,
            enrolled_admin_id: None,
            enrolled_credential_id: None,
            enrolled_trust_anchor_sha256: None,
        }
    }

    /// The reply after `bootstrap()` committed, its key `enrolled`.
    fn bootstrapped(enrolled: EnrolledState) -> Status {
        let request = bootstrap();
        Status {
            instance_id: Some(request.instance_id),
            recovery_key_epoch: Some(1),
            recovery_state_revision: Some(1),
            recovery_public_key: Some(request.recovery_public_key.as_bytes().to_vec()),
            enrolled_state: Some(enrolled),
            enrolled_admin_id: Some("admin".into()),
            enrolled_credential_id: Some("credential".into()),
            enrolled_trust_anchor_sha256: Some(
                Sha256::digest(request.trust_anchor_ref.as_bytes()).to_vec(),
            ),
            ..empty()
        }
    }

    /// The reconcile requests carry the original values only.
    #[test]
    fn the_reconcile_requests_carry_the_original_values() {
        let restore = ResponseRequest {
            operation_id: "operation".into(),
            signature: [1; 64],
        };
        assert!(
            StatusRequest::reconciling_restore(&restore)
                == StatusRequest {
                    operation_id: Some("operation".into()),
                    ..StatusRequest::default()
                }
        );
        assert!(
            StatusRequest::reconciling_bootstrap(&bootstrap())
                == StatusRequest {
                    credential_spki: Some(vec![0xc7; 44]),
                    ..StatusRequest::default()
                }
        );
    }

    /// Each operation state's verdict, by the restore procedure: restored
    /// committed; retired and revoked never; issued repeated; expiring
    /// asked again after its `settles_at`; expired not committed here; not
    /// found, no state and an expiring state without `settles_at`
    /// unknown. Only the state and `settles_at` decide.
    #[test]
    fn each_operation_state_has_its_restore_verdict() {
        let with = |state: Option<OperationState>, settles_at: Option<i64>| Status {
            operation_state: state,
            settles_at,
            ..empty()
        };
        let cases = [
            (Some(OperationState::Restored), RestoreVerdict::Committed),
            (Some(OperationState::Retired), RestoreVerdict::NeverCommits),
            (Some(OperationState::Revoked), RestoreVerdict::NeverCommits),
            (Some(OperationState::Issued), RestoreVerdict::RepeatRestore),
            (
                Some(OperationState::Expiring),
                RestoreVerdict::AskAgainAfter(7),
            ),
            (Some(OperationState::Expired), RestoreVerdict::Expired),
            (Some(OperationState::NotFound), RestoreVerdict::Unknown),
            (None, RestoreVerdict::Unknown),
        ];
        for (state, verdict) in cases {
            assert_eq!(
                RestoreVerdict::of(&with(state, Some(7))),
                verdict,
                "{state:?}"
            );
        }
        assert_eq!(
            RestoreVerdict::of(&with(Some(OperationState::Expiring), None)),
            RestoreVerdict::Unknown
        );
        for state in OperationState::ALL {
            if state != OperationState::Expiring {
                assert_eq!(
                    RestoreVerdict::of(&with(Some(state), None)),
                    RestoreVerdict::of(&with(Some(state), Some(7))),
                    "{state:?}"
                );
            }
        }
    }

    /// The bootstrap verdict: every member equal matches, whatever the
    /// credential's state (only an enabled one is usable); no instance is
    /// a repeat; each member that differs, or a key not enrolled or not
    /// asked, does not match.
    #[test]
    fn the_bootstrap_verdict_needs_every_member_equal() {
        let request = bootstrap();
        assert_eq!(
            BootstrapVerdict::of(&request, &bootstrapped(EnrolledState::Enabled)),
            BootstrapVerdict::Matches { enabled: true }
        );
        for state in [EnrolledState::Disabled, EnrolledState::Revoked] {
            assert_eq!(
                BootstrapVerdict::of(&request, &bootstrapped(state)),
                BootstrapVerdict::Matches { enabled: false },
                "{state:?}"
            );
        }
        // No recovery state: repeat, whatever else the reply says.
        assert_eq!(
            BootstrapVerdict::of(&request, &empty()),
            BootstrapVerdict::RepeatBootstrap
        );
        assert_eq!(
            BootstrapVerdict::of(
                &request,
                &Status {
                    instance_id: None,
                    ..bootstrapped(EnrolledState::Enabled)
                }
            ),
            BootstrapVerdict::RepeatBootstrap
        );
        let differing = [
            Status {
                instance_id: Some("other".into()),
                ..bootstrapped(EnrolledState::Enabled)
            },
            Status {
                recovery_public_key: Some(key(OTHER_KEY).as_bytes().to_vec()),
                ..bootstrapped(EnrolledState::Enabled)
            },
            Status {
                recovery_public_key: None,
                ..bootstrapped(EnrolledState::Enabled)
            },
            Status {
                enrolled_state: Some(EnrolledState::NotFound),
                enrolled_admin_id: None,
                enrolled_credential_id: None,
                enrolled_trust_anchor_sha256: None,
                ..bootstrapped(EnrolledState::Enabled)
            },
            // Not asked.
            Status {
                enrolled_state: None,
                ..bootstrapped(EnrolledState::Enabled)
            },
            // Another trust anchor (M17).
            Status {
                enrolled_trust_anchor_sha256: Some(
                    Sha256::digest("anchor \u{e9}".as_bytes()).to_vec(),
                ),
                ..bootstrapped(EnrolledState::Enabled)
            },
            // The digest of the escaped wire form, not of the string.
            Status {
                enrolled_trust_anchor_sha256: Some(Sha256::digest(b"anchor \xc3\xa9\\n").to_vec()),
                ..bootstrapped(EnrolledState::Enabled)
            },
            Status {
                enrolled_trust_anchor_sha256: None,
                ..bootstrapped(EnrolledState::Enabled)
            },
        ];
        for (at, status) in differing.iter().enumerate() {
            assert_eq!(
                BootstrapVerdict::of(&request, status),
                BootstrapVerdict::DoesNotMatch,
                "case {at}"
            );
        }
    }
}
