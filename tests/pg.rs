//! Target `pg`: conformance scenario tests of execution environment `pg`
//! (docs/testing/conformance-layout.md §1.1), run by the `scenarios-pg` CI
//! job as `cargo nextest run -p skyoauth-scenarios --test pg`.
//!
//! Every test needs `SKYOAUTH_IT_DATABASE_URL` and fails without it
//! ([`skyoauth_scenarios::pg::TestDb`]). Modules come from the layer
//! directories, so a test's full name is module-qualified, for example
//! `security::a29::a29_neg_binding_on_other_tenants_source`, and its
//! registry test ID is `nextest:skyoauth-scenarios/pg/<that name>`
//! (layout §3). `security::grant_fixture` is a helper module of the A38 and
//! A53 tests, and `security::selection_fixture` one of the A25 and A50
//! tests; neither is a scenario. The A22, A26, A32, A37, A43 and A53 tests
//! are partial: they are registered on their scenario's planned M1a stage
//! and count for nothing (see each module's docs). `harness::pg_teardown`
//! tests the harness's own database teardown (`src/pg.rs`); its tests are
//! not scenario tests, no name in it matches `a\d\d_`, and the registry
//! (`tests/conformance/scenarios.toml`) does not list them.

mod security {
    #[path = "a22.rs"]
    mod a22;
    #[path = "a24.rs"]
    mod a24;
    #[path = "a25.rs"]
    mod a25;
    #[path = "a26.rs"]
    mod a26;
    #[path = "a29.rs"]
    mod a29;
    #[path = "a32.rs"]
    mod a32;
    #[path = "a37.rs"]
    mod a37;
    #[path = "a38.rs"]
    mod a38;
    #[path = "a43.rs"]
    mod a43;
    #[path = "a50.rs"]
    mod a50;
    #[path = "a53.rs"]
    mod a53;
    #[path = "grant_fixture.rs"]
    mod grant_fixture;
    #[path = "selection_fixture.rs"]
    mod selection_fixture;
}

mod harness {
    #[path = "pg_teardown.rs"]
    mod pg_teardown;
}
