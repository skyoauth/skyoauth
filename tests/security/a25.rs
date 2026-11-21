//! A25: multiple same-audience grants, direct or with different target
//! services. Expected: the generated grant selector chooses the authorized
//! actor/target; an override, a wrong tenant or a wrong mode denies (tasks
//! §8; T12.3, T12.8, T21.4, T21.7).
//!
//! Stage M1a, "grant selection: each grant ID selects its own grant, actor,
//! target and eligible bindings among same-audience grants; a mode
//! override, a wrong or crossed tenant and a grant name select nothing,
//! with one error (registry API)": `registry::select_grant` and
//! `registry::match_binding` (ADR-015 item 4 steps 1, 3 and 4; design
//! section 5.7) against a real PostgreSQL, one fresh database per test,
//! seeded through the typed registry API by the shared fixture
//! (`tests/security/selection_fixture.rs`): two tenants, each with four
//! grants of one audience (direct of `wld_a`; delegations `wld_a` to
//! `svc_1`, `wld_a` to `svc_2` and `wld_b` to `svc_1`), three sources and
//! bindings whose IDs make any ineligible or other-actor binding sort
//! first. Every test runs in both tenants, and the cross-tenant ones in
//! both directions.
//!
//! - **Positive.** Each grant ID, in its own mode, on each source, selects
//!   exactly its stored grant (equal to `get_service_grant`), its actor and
//!   target (none for the direct grant), the stored source, and only the
//!   eligible bindings of its actor on that source, as stored
//!   (`a25_pos_each_grant_id_selects_its_own_actor_and_target`). Matching
//!   evidence that fits every binding of both actors on the source against
//!   a selection gives a binding of the grant's own actor, and a delegation
//!   keeps its own target service
//!   (`a25_pos_selection_then_match_names_the_grant_actor`).
//! - **Negative.** Each grant under each other mode
//!   (`a25_neg_mode_override_selects_nothing`), a grant or source of the
//!   other tenant, or both crossed (`a25_neg_wrong_tenant_selects_nothing`),
//!   and a grant's tenant-local name in place of its ID
//!   (`a25_neg_grant_name_is_not_a_selector`) select nothing. Every miss of
//!   these kinds, a doubly crossed tenant and unknown IDs included, is the
//!   same `SelectionError::NotSelectable`, with the same `Display` and
//!   `Debug` text, no source error and no selector in its text
//!   (`a25_neg_miss_reveals_no_cause`).
//!
//! "Selector" here is the `(tenant, grant ID, source ID, expected mode)`
//! that `select_grant` takes; the IDs are the fixture's, not generated
//! ones. Where several eligible bindings match, the one with the lowest ID
//! is selected: the spec says "stable ID ordering" without defining it, and
//! ascending byte order is the lead's reading (provisional), as in
//! `service/src/persistence/registry/selection.rs`. These tests do not
//! depend on it: each grant has one eligible binding per source, so
//! `match_binding` never chooses among several here, and which of several
//! matches wins is A50's. The ineligible bindings sort first under that
//! reading; the one check that relies on this computes the lowest matching
//! ID itself, only to show that a binding loaded by mistake would be the
//! one picked, so a change of the reading cannot fail A25.
//!
//! The fixture puts `github_production` bindings only on GitHub-issuer
//! sources and `generic_production` ones only on a non-GitHub source. The
//! ADR-016 item 4 check that a binding's template fits its source is not
//! built; once it is, it may refuse a `generic_production` template on a
//! GitHub source, which matters mainly to A50's bindings.
//!
//! Not covered here: the defensive matrices of the service tests
//! (`service/tests/registry_selection.rs`): the tenant and actor rechecks
//! with the `0004` foreign keys dropped
//! (`selection_rechecks_the_tenant_and_actor_the_foreign_keys_guarantee`),
//! the `WHERE EXISTS` gate that keeps a miss from decoding a corrupt row
//! (`a_miss_decodes_no_grant_row_even_a_corrupt_one`), disabled grants and
//! sources, the dormant impersonation grant, and a grant and source that
//! are both found but with no eligible binding on that source
//! (`every_miss_is_the_same_not_selectable`), and the exact-string matching
//! rules, near-miss claim names and values included. With the foreign keys
//! in place, a grant can list only bindings of its own actor, so the
//! statement's actor recheck cannot be observed here. The M2 stage: proof
//! verification at the selected source (step 2), subject and target
//! override (`select_grant` has no such parameter), the wire
//! `invalid_grant` of a miss (ERR-020), and generated selector IDs (T10.2).

use std::error::Error as _;

use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, EligibleBinding, GrantMode, Selection, SelectionError, match_binding, select_grant,
    },
};

use super::selection_fixture::{
    A, B, DIRECTIONS, GRANTS, Grant, SOURCES, Side, Source, two_tenants,
};

const MODES: [GrantMode; 3] = [
    GrantMode::Direct,
    GrantMode::Delegation,
    GrantMode::Impersonation,
];

async fn select(
    pool: &PgPool,
    tenant: &str,
    grant: &str,
    source: &str,
    mode: GrantMode,
) -> Result<Selection, SelectionError> {
    select_grant(pool, tenant, grant, source, mode).await
}

/// `grant` of `owner` on `source` of `owner`, in its own mode: selected.
async fn select_own(pool: &PgPool, owner: Side, grant: Grant, source: Source) -> Selection {
    select(
        pool,
        owner.tenant,
        &owner.id(grant.id),
        &source.id(owner),
        grant.mode,
    )
    .await
    .unwrap_or_else(|err| panic!("{} {grant:?} {source:?}: {err:?}", owner.tenant))
}

/// The selector selects nothing: `NotSelectable`, never a store error.
#[track_caller]
fn assert_not_selectable(result: Result<Selection, SelectionError>, case: &str) {
    match result {
        Err(SelectionError::NotSelectable) => {}
        other => panic!("{case}: expected NotSelectable: {other:?}"),
    }
}

#[tokio::test]
async fn a25_pos_each_grant_id_selects_its_own_actor_and_target() {
    let (db, pool) = two_tenants().await;
    for side in [A, B] {
        let t = side.tenant;
        for grant in GRANTS {
            let id = side.id(grant.id);
            let stored = registry::get_service_grant(&pool, t, &id).await.unwrap();
            for source in SOURCES {
                let selected = select_own(&pool, side, grant, source).await;
                let case = format!("{t} {id} {source:?}");
                // The stored grant, with its actor, target and mode, and the
                // stored source.
                assert_eq!(selected.grant, stored, "{case}");
                assert_eq!(
                    (
                        selected.grant.id.as_str(),
                        selected.grant.tenant_id.as_str(),
                        selected.grant.actor_principal_id.as_str(),
                        selected.grant.target_service_id.clone(),
                        selected.grant.mode,
                        selected.grant.resource_server_ids.clone(),
                    ),
                    (
                        id.as_str(),
                        t,
                        side.id(grant.actor).as_str(),
                        grant.target.map(|target| side.id(target)),
                        grant.mode,
                        vec![side.audience()],
                    ),
                    "{case}"
                );
                assert_eq!(
                    selected.source,
                    registry::get_trust_source(&pool, t, &source.id(side))
                        .await
                        .unwrap(),
                    "{case}"
                );
                // Only the grant's eligible binding on this source, as
                // stored: its actor's, on this source, enabled, listed.
                let own =
                    registry::get_principal_binding(&pool, t, &side.id(grant.eligible_on(source)))
                        .await
                        .unwrap();
                assert_eq!(own.workload_principal_id, side.id(grant.actor), "{case}");
                assert_eq!(own.trust_source_id, source.id(side), "{case}");
                assert_eq!(
                    selected.eligible_bindings,
                    [EligibleBinding {
                        id: own.id.clone(),
                        claim_match_policy: own.claim_match_policy.clone(),
                        revision: own.revision,
                    }],
                    "{case}"
                );
            }
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a25_pos_selection_then_match_names_the_grant_actor() {
    let (db, pool) = two_tenants().await;
    for side in [A, B] {
        let t = side.tenant;
        // Every binding of the tenant, enabled or not, listed or not, as an
        // eligible binding would carry it.
        let all = registry::list_principal_bindings(
            &pool,
            t,
            registry::Page::first(registry::MAX_PAGE_SIZE),
        )
        .await
        .unwrap();
        for source in SOURCES {
            let evidence = source.evidence();
            let on_source: Vec<EligibleBinding> = all
                .iter()
                .filter(|binding| binding.trust_source_id == source.id(side))
                .map(|binding| EligibleBinding {
                    id: binding.id.clone(),
                    claim_match_policy: binding.claim_match_policy.clone(),
                    revision: binding.revision,
                })
                .collect();
            // The evidence fits every binding on the source, of both actors,
            // so a binding loaded by mistake would match too.
            assert!(
                on_source.iter().all(|binding| binding.matches(&evidence)),
                "{t} {source:?}"
            );
            for actor in ["wld_a", "wld_b"] {
                assert!(
                    all.iter()
                        .any(|binding| binding.trust_source_id == source.id(side)
                            && binding.workload_principal_id == side.id(actor)),
                    "{t} {source:?} {actor}"
                );
            }
            for grant in GRANTS {
                let selected = select_own(&pool, side, grant, source).await;
                let case = format!("{t} {} {source:?}", side.id(grant.id));
                let matched = match_binding(&selected.eligible_bindings, &evidence)
                    .unwrap_or_else(|| panic!("{case}: no match"));
                assert_eq!(matched.id, side.id(grant.eligible_on(source)), "{case}");
                let stored = registry::get_principal_binding(&pool, t, &matched.id)
                    .await
                    .unwrap();
                assert_eq!(
                    (
                        stored.workload_principal_id.as_str(),
                        stored.trust_source_id.as_str(),
                    ),
                    (
                        selected.grant.actor_principal_id.as_str(),
                        selected.source.id.as_str(),
                    ),
                    "{case}"
                );
                assert_eq!(selected.grant.actor_principal_id, side.id(grant.actor));
                // A delegation keeps its own target service.
                assert_eq!(
                    selected.grant.target_service_id,
                    grant.target.map(|target| side.id(target)),
                    "{case}"
                );
                // Not vacuous: of every binding on the source that matches,
                // the one with the lowest ID in byte order is another one,
                // an ineligible or other-actor binding, wherever the fixture
                // sorts one first (on src_gh, and for the grant of wld_b on
                // every source). So a selection that loaded it would have it
                // picked. Byte order is the lead's provisional reading of
                // "stable ID ordering"; the lowest is computed here, not by
                // `match_binding`, so a change of that reading cannot fail
                // this test for a reason outside A25.
                if source == Source::Github || grant.actor == "wld_b" {
                    let lowest = on_source
                        .iter()
                        .filter(|binding| binding.matches(&evidence))
                        .min_by(|x, y| x.id.as_bytes().cmp(y.id.as_bytes()))
                        .unwrap();
                    assert_ne!(lowest.id, matched.id, "{case}");
                }
            }
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a25_neg_mode_override_selects_nothing() {
    let (db, pool) = two_tenants().await;
    for side in [A, B] {
        for grant in GRANTS {
            for source in SOURCES {
                for mode in MODES.into_iter().filter(|mode| *mode != grant.mode) {
                    let id = side.id(grant.id);
                    let src = source.id(side);
                    assert_not_selectable(
                        select(&pool, side.tenant, &id, &src, mode).await,
                        &format!("{} {id} {src} {mode}", side.tenant),
                    );
                }
                // The same selector in the grant's own mode selects it.
                select_own(&pool, side, grant, source).await;
            }
        }
    }
    db.drop([pool]).await;
}

/// For each grant and source of the owner, with the other tenant's grant
/// and source of the same role: the owner's grant and source through the
/// other tenant; the owner's grant with the other's source; the other's
/// grant with the owner's source, through the owner; and the owner's grant
/// with the other's source, through the other. Both directions.
#[tokio::test]
async fn a25_neg_wrong_tenant_selects_nothing() {
    let (db, pool) = two_tenants().await;
    for (owner, other) in DIRECTIONS {
        for grant in GRANTS {
            for source in SOURCES {
                let (own_grant, other_grant) = (owner.id(grant.id), other.id(grant.id));
                let (own_source, other_source) = (source.id(owner), source.id(other));
                for (tenant, grant_id, source_id) in [
                    (other.tenant, &own_grant, &own_source),
                    (owner.tenant, &own_grant, &other_source),
                    (owner.tenant, &other_grant, &own_source),
                    (other.tenant, &own_grant, &other_source),
                ] {
                    assert_not_selectable(
                        select(&pool, tenant, grant_id, source_id, grant.mode).await,
                        &format!("{tenant} {grant_id} {source_id}"),
                    );
                }
                // Each tenant selects its own.
                for side in [owner, other] {
                    select_own(&pool, side, grant, source).await;
                }
            }
        }
    }
    db.drop([pool]).await;
}

/// In both directions, a wrong tenant, the other tenant's source or grant,
/// both crossed, a mode override, a grant name and unknown IDs all give one
/// value: `NotSelectable`, with the same `Display` and `Debug` text across
/// every miss, no source error, and none of the selector's values in its
/// text.
#[tokio::test]
async fn a25_neg_miss_reveals_no_cause() {
    let (db, pool) = two_tenants().await;
    let direct = GRANTS[0];
    let delegation = GRANTS[3];
    let gh = Source::Github;
    let mut texts = Vec::new();
    for (owner, other) in DIRECTIONS {
        let own = owner.id(direct.id);
        let misses = [
            // A wrong tenant, the other tenant's source, the other tenant's
            // grant, and both crossed.
            (other.tenant, own.clone(), gh.id(owner), direct.mode),
            (owner.tenant, own.clone(), gh.id(other), direct.mode),
            (owner.tenant, other.id(direct.id), gh.id(owner), direct.mode),
            (other.tenant, own.clone(), gh.id(other), direct.mode),
            // Mode overrides.
            (
                owner.tenant,
                own.clone(),
                gh.id(owner),
                GrantMode::Delegation,
            ),
            (
                owner.tenant,
                owner.id(delegation.id),
                gh.id(owner),
                GrantMode::Impersonation,
            ),
            // The grant's tenant-local name in place of its ID.
            (owner.tenant, direct.name.into(), gh.id(owner), direct.mode),
            // Unknown tenant, grant and source.
            ("ten_none", own.clone(), gh.id(owner), direct.mode),
            (owner.tenant, "grt_none".into(), gh.id(owner), direct.mode),
            (owner.tenant, own.clone(), "src_none".into(), direct.mode),
        ];
        for (tenant, grant, source, mode) in &misses {
            let case = format!("{tenant} {grant} {source} {mode}");
            let err = select(&pool, tenant, grant, source, *mode)
                .await
                .expect_err(&case);
            assert!(
                matches!(err, SelectionError::NotSelectable),
                "{case}: {err:?}"
            );
            assert_eq!(err, SelectionError::NotSelectable, "{case}");
            assert!(err.source().is_none(), "{case}");
            let (display, debug) = (err.to_string(), format!("{err:?}"));
            for value in [*tenant, grant.as_str(), source.as_str(), mode.as_str()] {
                assert!(
                    !display.contains(value) && !debug.contains(value),
                    "{case}: {display:?} {debug:?}"
                );
            }
            texts.push((case, display, debug));
        }
    }
    // One text for every miss, of both directions.
    let (_, display, debug) = &texts[0];
    for (case, d, g) in &texts {
        assert_eq!((d, g), (display, debug), "{case}");
    }
    // The same selectors, corrected, select in both tenants.
    for side in [A, B] {
        select_own(&pool, side, direct, gh).await;
        select_own(&pool, side, delegation, gh).await;
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a25_neg_grant_name_is_not_a_selector() {
    let (db, pool) = two_tenants().await;
    for side in [A, B] {
        for grant in GRANTS {
            let stored = registry::get_service_grant(&pool, side.tenant, &side.id(grant.id))
                .await
                .unwrap();
            // The name is the grant's own, and differs from its ID.
            assert_eq!(stored.name, grant.name);
            assert_ne!(stored.name, stored.id);
            for source in SOURCES {
                let src = source.id(side);
                assert_not_selectable(
                    select(&pool, side.tenant, grant.name, &src, grant.mode).await,
                    &format!("{} {} {src}", side.tenant, grant.name),
                );
                select_own(&pool, side, grant, source).await;
            }
        }
    }
    db.drop([pool]).await;
}
