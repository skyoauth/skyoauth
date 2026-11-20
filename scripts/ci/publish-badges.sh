#!/bin/sh
# Publishes the Rust and TypeScript coverage and test-count badges for one
# source branch to the `badges` branch of the repository, under `<branch>/`,
# so a private repository can show them in its README without an external
# service.
#
#   scripts/ci/publish-badges.sh BRANCH SHA \
#       [--rust-coverage coverage.json] [--rust-junit junit.xml] \
#       [--ts-coverage coverage-summary.json] [--ts-results test-results.json]
#
# BRANCH is the source branch the figures were measured on and SHA the
# full commit they were measured at. At least one metric input must be
# passed:
#   --rust-coverage  `cargo llvm-cov --json --summary-only` report (line %)
#   --rust-junit     `cargo nextest` JUnit report (passed workspace tests)
#   --ts-coverage    Vitest `coverage-summary.json` report (line %)
#   --ts-results     Vitest `--reporter=json` test report (passed tests)
#
# Only the badges whose inputs are passed are regenerated; any other files
# already on the badges branch under `<branch>/` are preserved.
#
# Publications are ordered by the source branch, not by which CI run
# finished first: before generating anything and again before every push
# attempt, the script checks that BRANCH on the remote still points at SHA,
# and exits 0 without publishing ("superseded") when it does not, so a
# slower run for an older commit can never overwrite the badges of a newer
# one. A branch that has moved past SHA only by documentation changes
# (scripts/ci/docs-only.sh) still counts as at SHA: CI skips the coverage
# and test jobs for those, so these are the newest figures it will get. A
# branch that no longer exists on the remote counts as superseded.
#
# Every publication is generated on top of the current tip of the badges
# branch and pushed with a plain fast-forward. If the push is rejected
# because another publication landed meanwhile, the tip is fetched again
# and the files are regenerated on top of it; nothing is ever rebased or
# merged. Environment:
#   BADGES_REMOTE    git remote to push to (default: origin)
#   BADGES_BRANCH    branch that holds the badges (default: badges)
#   BADGES_ATTEMPTS  push attempts before giving up (default: 5)
#   GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL (and COMMITTER) for the commit
set -eu

branch=${1:?branch}
source_sha=${2:?source commit}
shift 2

rust_coverage=
rust_junit=
ts_coverage=
ts_results=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rust-coverage)
            rust_coverage=${2:?--rust-coverage requires a path}
            shift 2 ;;
        --rust-junit)
            rust_junit=${2:?--rust-junit requires a path}
            shift 2 ;;
        --ts-coverage)
            ts_coverage=${2:?--ts-coverage requires a path}
            shift 2 ;;
        --ts-results)
            ts_results=${2:?--ts-results requires a path}
            shift 2 ;;
        *)
            echo "publish-badges: unknown argument '$1'" >&2
            exit 2 ;;
    esac
done
if [ -z "$rust_coverage" ] && [ -z "$rust_junit" ] && [ -z "$ts_coverage" ] && [ -z "$ts_results" ]; then
    echo "publish-badges: at least one metric input is required" >&2
    exit 2
fi

remote=${BADGES_REMOTE:-origin}
badges_branch=${BADGES_BRANCH:-badges}
attempts=${BADGES_ATTEMPTS:-5}
here=$(cd "$(dirname "$0")" && pwd)

# Exits 0 (nothing to do) unless the source branch on the remote still
# points at the commit these figures were measured at, or has moved past
# it only by documentation changes.
source_is_current() {
    current=$(git ls-remote "$remote" "refs/heads/$branch" | awk 'NR == 1 { print $1 }')
    if [ "$current" = "$source_sha" ]; then
        return 0
    fi
    if [ -n "$current" ] &&
        git -c maintenance.auto=false -c gc.auto=0 fetch -q --depth=1 --no-write-fetch-head "$remote" "$current" 2>/dev/null &&
        sh "$here/docs-only.sh" "$source_sha" "$current" >/dev/null; then
        echo "publish-badges: $branch advanced from $source_sha to $current by documentation changes only; publishing"
        return 0
    fi
    echo "publish-badges: $branch advanced from $source_sha to ${current:-nothing (branch gone)}; superseded, not publishing"
    exit 0
}
source_is_current

coverage_color() {
    whole=${1%.*}
    if [ "$whole" -ge 90 ]; then printf '%s' brightgreen
    elif [ "$whole" -ge 80 ]; then printf '%s' green
    elif [ "$whole" -ge 70 ]; then printf '%s' yellowgreen
    elif [ "$whole" -ge 60 ]; then printf '%s' yellow
    else printf '%s' red
    fi
}

junit_attr() {
    sed -n "s/.*<testsuites[^>]*[[:space:]]$2=\"\([0-9][0-9]*\)\".*/\1/p" "$1" | head -n 1
}

rust_percent=
rust_color=
if [ -n "$rust_coverage" ]; then
    if ! jq -e '.data[0].totals.lines.percent | type == "number"' "$rust_coverage" >/dev/null; then
        echo "publish-badges: cannot read line coverage percentage from $rust_coverage" >&2
        exit 1
    fi
    rust_percent=$(jq '.data[0].totals.lines.percent' "$rust_coverage" | awk '{printf "%.1f", $1}')
    rust_color=$(coverage_color "$rust_percent")
fi

rust_passed=
if [ -n "$rust_junit" ]; then
    if [ ! -f "$rust_junit" ]; then
        echo "publish-badges: missing JUnit file $rust_junit" >&2
        exit 1
    fi
    j_tests=$(junit_attr "$rust_junit" tests)
    if [ -z "$j_tests" ]; then
        echo "publish-badges: cannot read tests count from $rust_junit" >&2
        exit 1
    fi
    j_skipped=$(junit_attr "$rust_junit" skipped)
    j_failures=$(junit_attr "$rust_junit" failures)
    j_errors=$(junit_attr "$rust_junit" errors)
    j_skipped=${j_skipped:-0}
    j_failures=${j_failures:-0}
    j_errors=${j_errors:-0}
    if [ "$j_failures" -ne 0 ] || [ "$j_errors" -ne 0 ]; then
        echo "publish-badges: refusing to publish rust tests with failures=$j_failures errors=$j_errors" >&2
        exit 1
    fi
    rust_passed=$((j_tests - j_skipped - j_failures - j_errors))
    if [ "$rust_passed" -lt 0 ]; then
        echo "publish-badges: invalid counts in $rust_junit (tests=$j_tests skipped=$j_skipped)" >&2
        exit 1
    fi
fi

ts_percent=
ts_color=
if [ -n "$ts_coverage" ]; then
    if ! jq -e '.total.lines.pct | type == "number"' "$ts_coverage" >/dev/null; then
        echo "publish-badges: cannot read line coverage percentage from $ts_coverage" >&2
        exit 1
    fi
    ts_percent=$(jq '.total.lines.pct' "$ts_coverage" | awk '{printf "%.1f", $1}')
    ts_color=$(coverage_color "$ts_percent")
fi

ts_passed=
if [ -n "$ts_results" ]; then
    if ! jq -e '.success == true and .numFailedTests == 0 and (.numPassedTests | type == "number" and . >= 0 and . == floor)' "$ts_results" >/dev/null; then
        echo "publish-badges: refusing to publish typescript tests from $ts_results" >&2
        exit 1
    fi
    ts_passed=$(jq '.numPassedTests' "$ts_results")
fi

details=
append_detail() {
    if [ -n "$details" ]; then
        details="$details, $1"
    else
        details="$1"
    fi
}
if [ -n "$rust_percent" ]; then append_detail "rust ${rust_percent}% lines"; fi
if [ -n "$rust_passed" ]; then append_detail "rust ${rust_passed} tests"; fi
if [ -n "$ts_percent" ]; then append_detail "typescript ${ts_percent}% lines"; fi
if [ -n "$ts_passed" ]; then append_detail "typescript ${ts_passed} tests"; fi

sha=$(git rev-parse --short "$source_sha")

# Every attempt gets a worktree of its own: reusing one path would reuse
# its `.git/worktrees/<name>` entry, and a `worktree add` racing with
# the removal of the previous attempt's entry has been seen to fail.
# Nothing else may prune entries meanwhile either: a fetch can leave a
# detached auto-maintenance process behind, and `git gc` prunes
# worktrees, so maintenance is off for this script's fetches; and since a
# `worktree add` that still lost its fresh entry has been seen once on a
# CI runner ("could not open .git/worktrees/<name>/locked"), the add is
# retried after a prune before the attempt is given up.
work=
cleanup() {
    if [ -n "$work" ]; then
        git worktree remove --force "$work" 2>/dev/null || rm -rf "$work"
    fi
    git worktree prune 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# `add_worktree NAME [COMMIT]`: `git worktree add --detach`, retried.
add_worktree() {
    tries=0
    while :; do
        tries=$((tries + 1))
        if git worktree add -q --detach "$@" 2>"$work.err"; then
            rm -f "$work.err"
            return 0
        fi
        if [ "$tries" -ge 3 ]; then
            cat "$work.err" >&2
            rm -f "$work.err"
            return 1
        fi
        echo "publish-badges: worktree add failed ($(tr '\n' ' ' < "$work.err")); retrying" >&2
        git worktree remove --force "$1" 2>/dev/null || rm -rf "$1"
        git worktree prune 2>/dev/null || true
        sleep 1
    done
}

n=0
while :; do
    n=$((n + 1))
    cleanup
    work=$(mktemp -d)
    rmdir "$work"
    if git -c maintenance.auto=false -c gc.auto=0 fetch -q "$remote" "$badges_branch" 2>/dev/null; then
        add_worktree "$work" FETCH_HEAD
    else
        # First publication: an empty orphan branch.
        add_worktree "$work"
        (cd "$work" && git checkout -q --orphan "$badges_branch" && git rm -rfq . >/dev/null)
    fi

    out="$work/$branch"
    mkdir -p "$out"
    if [ -n "$rust_percent" ]; then
        sh "$here/badge.sh" "rust coverage" "${rust_percent}%" "$rust_color" > "$out/rust-coverage.svg"
    fi
    if [ -n "$rust_passed" ]; then
        sh "$here/badge.sh" "rust tests" "$rust_passed passed" brightgreen > "$out/rust-tests.svg"
    fi
    if [ -n "$ts_percent" ]; then
        sh "$here/badge.sh" "typescript coverage" "${ts_percent}%" "$ts_color" > "$out/typescript-coverage.svg"
    fi
    if [ -n "$ts_passed" ]; then
        sh "$here/badge.sh" "typescript tests" "$ts_passed passed" brightgreen > "$out/typescript-tests.svg"
    fi

    if [ -s "$out/summary.json" ] && jq -e 'type == "object"' "$out/summary.json" >/dev/null 2>&1; then
        base_summary=$(cat "$out/summary.json")
    else
        base_summary='{}'
    fi
    printf '%s' "$base_summary" | jq -c \
        --arg branch "$branch" \
        --arg commit "$sha" \
        --arg rust_lines "$rust_percent" \
        --arg rust_tests "$rust_passed" \
        --arg ts_lines "$ts_percent" \
        --arg ts_tests "$ts_passed" \
        '.branch = $branch
         | .commit = $commit
         | if $rust_lines != "" then .rust_lines_percent = ($rust_lines | tonumber) else . end
         | if $rust_tests != "" then .rust_tests_passed = ($rust_tests | tonumber) else . end
         | if $ts_lines != "" then .typescript_lines_percent = ($ts_lines | tonumber) else . end
         | if $ts_tests != "" then .typescript_tests_passed = ($ts_tests | tonumber) else . end' \
        > "$out/summary.json"

    git -C "$work" add -A
    if git -C "$work" diff --cached --quiet; then
        echo "badges unchanged for $branch ($details)"
        exit 0
    fi
    git -C "$work" commit -q -m "badges: $branch at $sha ($details)"
    source_is_current
    if git -C "$work" push -q "$remote" "HEAD:refs/heads/$badges_branch" 2>/dev/null; then
        echo "published $branch to $remote/$badges_branch ($details, commit $sha, attempt $n)"
        exit 0
    fi
    if [ "$n" -ge "$attempts" ]; then
        echo "publish-badges: push rejected $n times; giving up" >&2
        exit 1
    fi
    echo "publish-badges: push rejected (another publication landed); regenerating on the new tip"
done
