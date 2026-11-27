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
//! A53 tests (its `github_policy` also of the A26, A29 and A43 tests and of
//! `security::selection_fixture`), `security::selection_fixture` one of the
//! A02, A25 and A50 tests, and `security::egress_fixture` one of every test
//! that writes trust sources through the bare registry writers (A02, A22,
//! A24, A25, A26, A29, A37, A38, A43, A50, A53 and A54). The egress fixture
//! bootstraps the instance, or adopts one the test bootstrapped, and writes
//! the sources' egress allowlist entries through the audited egress
//! allowlist writer. `security::wire_fixture` is a helper module of the A22
//! and A49 wire tests: the wire error catalogue reader, requests through
//! the admin router, the keys and the operation seeding. None of them is a
//! scenario. A scenario's tests
//! may be in more than one module: a `security::aNN_wire` module drives the
//! admin read router of `skyoauth_service::admin_http` with an
//! already-verified peer, next to `security::aNN`. Some modules hold
//! partial tests, registered on a planned stage and counting for nothing;
//! this comment does not list which: the stages' `tests` in the registry
//! (`tests/conformance/scenarios.toml`) are the source, layout §2
//! "Partial tests" is generated from them, and each module's docs say what
//! its tests cover.
//! `harness::pg_teardown`
//! tests the harness's own database teardown (`src/pg.rs`),
//! `harness::wire_errors` the wire error catalogue
//! `tests/conformance/fixtures/_wire/errors.v1.json` against the service's
//! `admin_http::ErrorCode` (no server needed),
//! `harness::wire_fixture_keys` pins `security::wire_fixture::key` to
//! known answers (no database needed), `harness::recovery_key_fixture`
//! feeds the cases of `tests/conformance/fixtures/_recovery/key.v1.json`
//! to the service's recovery key checks (through bootstrap and the
//! challenge issue, on a database), `harness::public_identity_fixture`
//! those of `_recovery/public_identity.v1.json` to its
//! `canonical_public_identity` (no database needed),
//! `harness::recovery_challenge_fixture` checks the vectors of
//! `_recovery/challenge.v1.json` against its `DigestEnvelope` (no database
//! needed) and its `issue_recovery_challenge` (on a database), and
//! `harness::local_transport_wire` checks `_wire/local_transport.v1.json`
//! against its `local_transport` (constants and golden request lines with
//! no database, the golden exchange on one), and
//! `harness::recovery_signature_fixture` checks the cases of
//! `_recovery/signature.v1.json`, signed with the test keys of
//! `_recovery/recovery.test-key.json`, against its
//! `preview_recovery_response` and `restore_operator` (on a database): the
//! cases the `skyoauth-operator` tests check against the workstation's
//! copies; `harness::socket_path_fixture` (Unix only) builds the trees of
//! `_wire/socket_path.v1.json` and binds its `local_transport` in each, as
//! the operator's socket path checks are run on the same trees (no
//! database needed; the cases that need root, or as root the peer user
//! `SKYOAUTH_IT_PEER_USER`, print a notice); `harness::local_client_round_trip`
//! (Unix only) runs the `skyoauth-operator` library's `LocalClient`
//! against the service's `LocalTransport` on a socket in a private
//! directory (on a database): the bootstrap, a signed restore and their
//! reconcile, the page walk over more than a page with a tie, and every
//! operation state. Their tests are not scenario tests, no name in them matches `a\d\d_`, and the registry
//! (`tests/conformance/scenarios.toml`) does not list them.

mod security {
    #[path = "a02.rs"]
    mod a02;
    #[path = "a04.rs"]
    mod a04;
    #[path = "a05.rs"]
    mod a05;
    #[path = "a22.rs"]
    mod a22;
    #[path = "a22_wire.rs"]
    mod a22_wire;
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
    #[path = "a48.rs"]
    mod a48;
    #[path = "a49.rs"]
    mod a49;
    #[path = "a49_wire.rs"]
    mod a49_wire;
    #[path = "a50.rs"]
    mod a50;
    #[path = "a53.rs"]
    mod a53;
    #[path = "a54.rs"]
    mod a54;
    #[path = "egress_fixture.rs"]
    mod egress_fixture;
    #[path = "grant_fixture.rs"]
    mod grant_fixture;
    #[path = "selection_fixture.rs"]
    mod selection_fixture;
    #[path = "wire_fixture.rs"]
    pub(crate) mod wire_fixture;
}

mod harness {
    // Where the service binds (Linux on x86_64, aarch64 and riscv64: the
    // same targets as `BINDS_SUPPORTED` in `socket_path_fixture.rs`); on
    // other targets there is no transport to talk to, so the module is not
    // compiled.
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    #[path = "local_client_round_trip.rs"]
    mod local_client_round_trip;
    #[cfg(unix)]
    #[path = "local_transport_wire.rs"]
    mod local_transport_wire;
    #[path = "pg_teardown.rs"]
    mod pg_teardown;
    #[path = "public_identity_fixture.rs"]
    mod public_identity_fixture;
    #[path = "recovery_challenge_fixture.rs"]
    mod recovery_challenge_fixture;
    #[path = "recovery_key_fixture.rs"]
    mod recovery_key_fixture;
    #[path = "recovery_signature_fixture.rs"]
    mod recovery_signature_fixture;
    #[cfg(unix)]
    #[path = "socket_path_fixture.rs"]
    mod socket_path_fixture;
    #[path = "wire_errors.rs"]
    mod wire_errors;
    #[path = "wire_fixture_keys.rs"]
    mod wire_fixture_keys;
}
