//! Shared helpers of the conformance scenario tests
//! (docs/testing/conformance-layout.md §1.2). The tests themselves are the
//! package's test targets, one per execution environment; each target root
//! declares its scenario modules from the layer directories (`security/`,
//! `conformance/`, `integration/`) with `#[path]`.
//!
//! The package is not part of the Rust coverage gate and is excluded from
//! the `rust` job's tests: its targets need their environment and fail
//! loudly without it.
//! A `#[test]` or doctest in this library would run in no CI job: the
//! `rust` job excludes the package and `scenarios-pg` runs only `--test pg`.

pub mod pg;
