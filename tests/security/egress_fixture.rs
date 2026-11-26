//! Egress allowlist entries for the trust sources that scenarios write
//! through the bare registry writers; a helper module of the `pg` target,
//! not a scenario (no test, no name matching `a\d\d_`).
//!
//! Since migration `0011` (service/migrations/README.md, "What 0011 adds";
//! provisional lead pick, 2026-11-22) the database refuses a trust source
//! whose `discovery_url` or `token_review_endpoint` has no enabled egress
//! allowlist entry of its purpose with exactly that value (`23514`,
//! `trust_source_discovery_url_egress_enabled` or
//! `trust_source_token_review_endpoint_egress_enabled`). A scenario that
//! creates sources with `registry::test_support::create_trust_source` first
//! allows their destinations with [`Egress::allow_destinations`].
//!
//! Every entry is written through the audited egress allowlist writer,
//! `skyoauth_service::admin::create_egress_entry` (IR-152; slice S2a), by
//! an instance `security_admin`, with no SQL of this module's own:
//!
//! - [`Egress::bootstrap`] bootstraps the instance with this fixture's own
//!   first operator (`adm_egress`, key [`KEY`]), for a scenario that does
//!   not bootstrap itself. Its operator, instance ID and bootstrap event ID
//!   are this module's, distinct from every scenario's (`adm_first`,
//!   `aud_bootstrap` and the others).
//! - [`Egress::adopt`] writes as an instance `security_admin` of an
//!   instance the scenario bootstrapped itself (A54).
//!
//! A create is widening (IR-052, IR-152), so it is acknowledged
//! (`acknowledge_widening`) and applies only while
//! `widening_second_approver` is off (outcome `success_widening`) or under
//! `single_actor_mode` (`success_single_actor`); otherwise it is
//! `SecondApproverRequired` and the fixture panics. A scenario that turns
//! the gate on allows its destinations first (A54). Each create appends one instance audit event
//! (`egress_allowlist_entry.create`), after the bootstrap's
//! `recovery_state.create`; a scenario that compares the audit chain reads
//! its head after the fixture.
//!
//! The IDs of the entries and of their events come from one
//! [`SequentialIds`] per [`Egress`], whose seed no other [`Egress`] of the
//! process shares (from [`NEXT_SEED`]), and which no scenario generator
//! uses, so no ID is given twice in a database.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use skyoauth_service::admin::{self, AdminRequest, EgressEntryCreate};
use skyoauth_service::ids::test_support::SequentialIds;
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, BootstrapRequest, EgressAllowlistEntry, EgressPurpose, MAX_PAGE_SIZE, NewTrustSource,
        Page, Status, bootstrap_instance,
    },
};
use sqlx::PgConnection;

/// The credential key of the fixture's first operator, `adm_egress`.
const KEY: &str = "spki-sha256:egress-fixture";

/// The seed of the next [`Egress`]'s generator: a range of this module's
/// own (A05 starts at `0x0a05_0000`, A49 uses 49).
static NEXT_SEED: AtomicU64 = AtomicU64::new(0x0e9e_0000);

/// The time of the fixture's bootstrap and of its writes' events.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

/// The writer of the egress allowlist entries of one test's database.
pub(super) struct Egress {
    /// The key of the instance `security_admin` that writes the entries.
    public_identity: &'static str,
    ids: SequentialIds,
}

impl Egress {
    /// Bootstraps the instance with the fixture's first operator
    /// `adm_egress` (credential `crd_egress`, key [`KEY`], binding
    /// `rb_egress`, instance `security_admin`); with no policy row seeded,
    /// it is inserted with both flags off. Panics when bootstrap fails, for example on an
    /// instance already bootstrapped (use [`Egress::adopt`] there).
    pub(super) async fn bootstrap(pool: &PgPool) -> Self {
        let mut transaction = pool.begin().await.unwrap();
        bootstrap_instance(
            &mut transaction,
            &BootstrapRequest {
                instance_id: "019a9f3c-5b2e-7c41-9d8e-0000000e9e55",
                admin_id: "adm_egress",
                credential_id: "crd_egress",
                public_identity: KEY,
                trust_anchor_ref: "deployment/operator-ca",
                binding_id: "rb_egress",
                recovery_public_key: &[0x11; 32],
                audit_event_id: "aud_egress_bootstrap",
                now: now(),
            },
        )
        .await
        .unwrap_or_else(|err| panic!("egress fixture bootstrap: {err}"));
        transaction.commit().await.unwrap();
        Self::adopt(KEY)
    }

    /// Writes as `public_identity`, an enabled instance `security_admin` of
    /// an instance the scenario bootstrapped itself.
    pub(super) fn adopt(public_identity: &'static str) -> Self {
        Self {
            public_identity,
            ids: SequentialIds::with_seed(NEXT_SEED.fetch_add(1, Ordering::Relaxed)),
        }
    }

    /// Creates an enabled egress allowlist entry through
    /// `admin::create_egress_entry`, acknowledged as widening, for each
    /// destination `source` sets: `discovery_url` with purpose
    /// `oidc_discovery` and `token_review_endpoint` with purpose
    /// `token_review`. A destination whose entry of the purpose exists and
    /// is enabled is skipped, found through the registry's list first, so
    /// sources that share a destination may each call this.
    ///
    /// # Panics
    ///
    /// When the write fails (the gate on without `single_actor_mode`, an
    /// operator that is not an instance `security_admin`, an invalid
    /// destination), or when the entry exists and is disabled: this
    /// fixture does not enable entries.
    pub(super) async fn allow_destinations(&self, pool: &PgPool, source: &NewTrustSource) {
        for (purpose, destination) in [
            (
                EgressPurpose::OidcDiscovery,
                source.discovery_url.as_deref(),
            ),
            (
                EgressPurpose::TokenReview,
                source.token_review_endpoint.as_deref(),
            ),
        ] {
            let Some(destination) = destination else {
                continue;
            };
            let mut transaction = pool.begin().await.unwrap();
            if let Some(entry) = find(&mut transaction, purpose, destination).await {
                assert_eq!(
                    entry.status,
                    Status::Enabled,
                    "the {purpose:?} entry of the egress fixture is disabled"
                );
                transaction.rollback().await.unwrap();
                continue;
            }
            let request = AdminRequest {
                public_identity: self.public_identity,
                ids: &self.ids,
                now: now(),
            };
            let new = EgressEntryCreate {
                purpose,
                exact_destination: destination.into(),
                status: Status::Enabled,
            };
            admin::create_egress_entry(&mut transaction, &request, &new, true)
                .await
                .unwrap_or_else(|err| {
                    panic!("egress entry for a {purpose:?} destination: {err:?}")
                });
            transaction.commit().await.unwrap();
        }
    }
}

/// The entry of `purpose` for exactly `destination`, read page by page
/// through the registry's list.
async fn find(
    connection: &mut PgConnection,
    purpose: EgressPurpose,
    destination: &str,
) -> Option<EgressAllowlistEntry> {
    let mut after: Option<String> = None;
    loop {
        let page = match after.as_deref() {
            None => Page::first(MAX_PAGE_SIZE),
            Some(id) => Page::after(id, MAX_PAGE_SIZE),
        };
        let entries = registry::list_egress_allowlist_entries(&mut *connection, page)
            .await
            .unwrap();
        let full = entries.len() == usize::try_from(MAX_PAGE_SIZE).unwrap();
        after = entries.last().map(|entry| entry.id.clone());
        if let Some(entry) = entries
            .into_iter()
            .find(|entry| entry.purpose == purpose && entry.exact_destination == destination)
        {
            return Some(entry);
        }
        if !full {
            return None;
        }
    }
}
