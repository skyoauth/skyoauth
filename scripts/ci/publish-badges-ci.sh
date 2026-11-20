#!/bin/sh
# Runs publish-badges.sh for the `publish-badges` CI job: turns the results
# and report flags of the jobs it needs into publish-badges.sh arguments.
# Everything comes from the environment, which the workflow sets from
# `needs` (no expression is interpolated into the script):
#
#   GITHUB_REF_NAME, GITHUB_SHA  the branch and commit measured
#   RUST_COVERAGE_OK      `true` when rust-coverage left a complete report
#   RUST_COVERAGE_RESULT  result of rust-coverage
#   RUST_TESTS_RESULT     result of service-nextest
#   TS_OK, TS_RESULT      the same as RUST_COVERAGE_* for typescript-coverage
#
# Report paths are relative to the current directory, where the job
# downloads the artifacts.
#
# A job that succeeded must have left a usable report. A missing one fails
# this script rather than silently keeping the previous badge, but only
# after the badges that are known have been published, so that a red
# update (for instance, failed tests) is never dropped. A cancelled job
# counts as failed, so no badge stays green while the run that should have
# refreshed it went red. Exits with publish-badges.sh's status when that
# failed, else 1 when a report was missing, else 0.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fail=0
missing() {
    echo "publish-badges: $1" >&2
    fail=1
}

set -- "${GITHUB_REF_NAME:?}" "${GITHUB_SHA:?}"

rust_coverage_result=${RUST_COVERAGE_RESULT:-}
if [ "${RUST_COVERAGE_OK:-}" = true ]; then
    set -- "$@" --rust-coverage target/coverage/coverage.json --rust-coverage-result "$rust_coverage_result"
elif [ "$rust_coverage_result" = success ]; then
    missing "rust-coverage succeeded without a complete coverage report"
elif [ "$rust_coverage_result" = failure ] || [ "$rust_coverage_result" = cancelled ]; then
    set -- "$@" --rust-coverage-failed
fi

rust_tests_result=${RUST_TESTS_RESULT:-skipped}
if [ "$rust_tests_result" != skipped ]; then
    junit=
    if [ -d target/nextest-artifacts ]; then
        junit=$(find target/nextest-artifacts -maxdepth 2 -name junit.xml | sort -V | tail -n 1)
    fi
    if [ -n "$junit" ]; then
        set -- "$@" --rust-junit "$junit"
    elif [ "$rust_tests_result" = success ]; then
        missing "service-nextest succeeded without a junit.xml"
    fi
    if [ "$rust_tests_result" != success ]; then
        set -- "$@" --rust-tests-failed
    fi
fi

ts_result=${TS_RESULT:-}
if [ "${TS_OK:-}" = true ]; then
    set -- "$@" --ts-coverage clients/typescript/coverage/coverage-summary.json \
        --ts-coverage-result "$ts_result" \
        --ts-results clients/typescript/coverage/test-results.json
elif [ "$ts_result" = success ]; then
    missing "typescript-coverage succeeded without a complete coverage report"
elif [ "$ts_result" = failure ] || [ "$ts_result" = cancelled ]; then
    set -- "$@" --ts-coverage-failed --ts-tests-failed
    if [ -s clients/typescript/coverage/test-results.json ]; then
        set -- "$@" --ts-results clients/typescript/coverage/test-results.json
    fi
fi

if [ "$#" -le 2 ]; then
    echo "publish-badges: no badge to publish"
    exit "$fail"
fi
status=0
sh "$here/publish-badges.sh" "$@" || status=$?
if [ "$status" -ne 0 ]; then
    exit "$status"
fi
exit "$fail"
