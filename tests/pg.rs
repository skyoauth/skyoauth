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
//! A53 tests, not a scenario.

mod security {
    #[path = "a29.rs"]
    mod a29;
    #[path = "a38.rs"]
    mod a38;
    #[path = "a53.rs"]
    mod a53;
    #[path = "grant_fixture.rs"]
    mod grant_fixture;
}
