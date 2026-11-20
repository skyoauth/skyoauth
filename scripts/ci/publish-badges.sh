#!/bin/sh
# Publishes the Rust and TypeScript coverage and test-count badges for one
# source branch to the `badges` branch of the repository, under `<branch>/`,
# so a private repository can show them in its README without an external
# service.
#
#   scripts/ci/publish-badges.sh BRANCH SHA \
#       [--rust-coverage coverage.json | --rust-coverage-failed] \
#       [--rust-junit junit.xml] [--rust-tests-failed] \
#       [--ts-coverage coverage-summary.json | --ts-coverage-failed] \
#       [--ts-results test-results.json] [--ts-tests-failed]
#
# BRANCH is the source branch the figures were measured on and SHA the
# full commit they were measured at. At least one metric input must be
# passed:
#   --rust-coverage         `cargo llvm-cov --json --summary-only` report (line %)
#   --rust-coverage-failed  publish a red `failing` rust coverage badge
#   --rust-junit            `cargo nextest` JUnit report (passed or failed tests)
#   --rust-tests-failed     mark the rust tests job as failed (uses the JUnit
#                           failure count when present, else red `failing`)
#   --ts-coverage           Vitest `coverage-summary.json` report (line %)
#   --ts-coverage-failed    publish a red `failing` typescript coverage badge
#   --ts-results            Vitest `--reporter=json` test report
#   --ts-tests-failed       mark the typescript tests job as failed (uses the
#                           JSON failure count when present, else red `failing`)
#
# Only the badges whose inputs are passed are regenerated; any other files
# already on the badges branch under `<branch>/` are preserved, and each
# entry in `summary.json` records its own source commit so partial updates
# never misattribute an older metric to a newer commit.
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
# branch and pushed with a plain fast-forward. If the push is rejected as a
# non-fast-forward because another publication landed meanwhile, the tip is
# fetched again and the files are regenerated on top of it; non-retryable
# push errors fail immediately with stderr intact. Environment:
#   BADGES_REMOTE       git remote to push to (default: origin)
#   BADGES_BRANCH       branch that holds the badges (default: badges)
#   BADGES_ATTEMPTS     push attempts before giving up (default: 5)
#   BADGES_RETRY_SLEEP  seconds to sleep before retrying a rejected push (default: 1)
#   GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL (and COMMITTER) for the commit
set -eu

branch=${1:?branch}
source_sha=${2:?source commit}
shift 2

rust_coverage=
rust_coverage_failed=0
rust_junit=
rust_tests_failed=0
ts_coverage=
ts_coverage_failed=0
ts_results=
ts_tests_failed=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rust-coverage)
            rust_coverage=${2:?--rust-coverage requires a path}
            shift 2 ;;
        --rust-coverage-failed)
            rust_coverage_failed=1
            shift ;;
        --rust-junit)
            rust_junit=${2:?--rust-junit requires a path}
            shift 2 ;;
        --rust-tests-failed)
            rust_tests_failed=1
            shift ;;
        --ts-coverage)
            ts_coverage=${2:?--ts-coverage requires a path}
            shift 2 ;;
        --ts-coverage-failed)
            ts_coverage_failed=1
            shift ;;
        --ts-results)
            ts_results=${2:?--ts-results requires a path}
            shift 2 ;;
        --ts-tests-failed)
            ts_tests_failed=1
            shift ;;
        *)
            echo "publish-badges: unknown argument '$1'" >&2
            exit 2 ;;
    esac
done
if [ -n "$rust_coverage" ] && [ "$rust_coverage_failed" -eq 1 ]; then
    echo "publish-badges: --rust-coverage and --rust-coverage-failed are mutually exclusive" >&2
    exit 2
fi
if [ -n "$ts_coverage" ] && [ "$ts_coverage_failed" -eq 1 ]; then
    echo "publish-badges: --ts-coverage and --ts-coverage-failed are mutually exclusive" >&2
    exit 2
fi
if [ -z "$rust_coverage" ] && [ "$rust_coverage_failed" -eq 0 ] &&
    [ -z "$rust_junit" ] && [ "$rust_tests_failed" -eq 0 ] &&
    [ -z "$ts_coverage" ] && [ "$ts_coverage_failed" -eq 0 ] &&
    [ -z "$ts_results" ] && [ "$ts_tests_failed" -eq 0 ]; then
    echo "publish-badges: at least one metric input is required" >&2
    exit 2
fi

remote=${BADGES_REMOTE:-origin}
badges_branch=${BADGES_BRANCH:-badges}
attempts=${BADGES_ATTEMPTS:-5}
retry_sleep=${BADGES_RETRY_SLEEP:-1}
here=$(cd "$(dirname "$0")" && pwd)

# Exits 0 (nothing to do) unless the source branch on the remote still
# points at the commit these figures were measured at, or has moved past
# it only by documentation changes.
source_is_current() {
    remote_ref=$(git ls-remote "$remote" "refs/heads/$branch")
    current=$(printf '%s\n' "$remote_ref" | awk 'NR == 1 { print $1 }')
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

sha=$(git rev-parse --short "$source_sha")

# Rust coverage badge state.
rust_cov_value=
rust_cov_color=
rust_cov_json=
if [ -n "$rust_coverage" ]; then
    if ! jq -e '.data[0].totals.lines.percent | type == "number"' "$rust_coverage" >/dev/null; then
        echo "publish-badges: cannot read line coverage percentage from $rust_coverage" >&2
        exit 1
    fi
    rust_percent=$(jq '.data[0].totals.lines.percent' "$rust_coverage" | awk '{printf "%.1f", $1}')
    rust_cov_value="${rust_percent}%"
    rust_cov_color=$(coverage_color "$rust_percent")
    rust_cov_json=$(jq -nc --arg p "$rust_percent" --arg c "$sha" \
        '{status: "ok", lines_percent: ($p | tonumber), commit: $c}')
elif [ "$rust_coverage_failed" -eq 1 ]; then
    rust_cov_value=failing
    rust_cov_color=red
    rust_cov_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
fi

# Rust tests badge state.
rust_tests_value=
rust_tests_color=
rust_tests_json=
if [ -n "$rust_junit" ]; then
    j_tests=
    if [ -f "$rust_junit" ]; then
        j_tests=$(junit_attr "$rust_junit" tests)
    fi
    if [ -z "$j_tests" ]; then
        if [ "$rust_tests_failed" -eq 1 ]; then
            rust_tests_value=failing
            rust_tests_color=red
            rust_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
        else
            echo "publish-badges: cannot read tests count from $rust_junit" >&2
            exit 1
        fi
    else
        j_skipped=$(junit_attr "$rust_junit" skipped)
        j_failures=$(junit_attr "$rust_junit" failures)
        j_errors=$(junit_attr "$rust_junit" errors)
        j_skipped=${j_skipped:-0}
        j_failures=${j_failures:-0}
        j_errors=${j_errors:-0}
        rust_failed=$((j_failures + j_errors))
        rust_passed=$((j_tests - j_skipped - rust_failed))
        if [ "$rust_passed" -lt 0 ]; then
            if [ "$rust_tests_failed" -eq 1 ]; then
                rust_tests_value=failing
                rust_tests_color=red
                rust_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
            else
                echo "publish-badges: invalid counts in $rust_junit (tests=$j_tests skipped=$j_skipped failed=$rust_failed)" >&2
                exit 1
            fi
        elif [ "$rust_failed" -gt 0 ]; then
            rust_tests_value="$rust_failed failed"
            rust_tests_color=red
            rust_tests_json=$(jq -nc --argjson p "$rust_passed" --argjson f "$rust_failed" --arg c "$sha" \
                '{status: "failed", passed: $p, failed: $f, commit: $c}')
        elif [ "$rust_tests_failed" -eq 1 ]; then
            rust_tests_value=failing
            rust_tests_color=red
            rust_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
        else
            rust_tests_value="$rust_passed passed"
            rust_tests_color=brightgreen
            rust_tests_json=$(jq -nc --argjson p "$rust_passed" --arg c "$sha" \
                '{status: "passed", passed: $p, failed: 0, commit: $c}')
        fi
    fi
elif [ "$rust_tests_failed" -eq 1 ]; then
    rust_tests_value=failing
    rust_tests_color=red
    rust_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
fi

# TypeScript coverage badge state.
ts_cov_value=
ts_cov_color=
ts_cov_json=
if [ -n "$ts_coverage" ]; then
    if ! jq -e '.total.lines.pct | type == "number"' "$ts_coverage" >/dev/null; then
        echo "publish-badges: cannot read line coverage percentage from $ts_coverage" >&2
        exit 1
    fi
    ts_percent=$(jq '.total.lines.pct' "$ts_coverage" | awk '{printf "%.1f", $1}')
    ts_cov_value="${ts_percent}%"
    ts_cov_color=$(coverage_color "$ts_percent")
    ts_cov_json=$(jq -nc --arg p "$ts_percent" --arg c "$sha" \
        '{status: "ok", lines_percent: ($p | tonumber), commit: $c}')
elif [ "$ts_coverage_failed" -eq 1 ]; then
    ts_cov_value=failing
    ts_cov_color=red
    ts_cov_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
fi

# TypeScript tests badge state.
ts_tests_value=
ts_tests_color=
ts_tests_json=
if [ -n "$ts_results" ]; then
    if [ -s "$ts_results" ] &&
        jq -e '(.success | type == "boolean") and (.numPassedTests | type == "number" and . >= 0 and . == floor) and (.numFailedTests | type == "number" and . >= 0 and . == floor)' "$ts_results" >/dev/null 2>&1; then
        ts_success=$(jq -r '.success' "$ts_results")
        ts_passed=$(jq '.numPassedTests' "$ts_results")
        ts_failed=$(jq '.numFailedTests' "$ts_results")
        if [ "$ts_failed" -gt 0 ]; then
            ts_tests_value="$ts_failed failed"
            ts_tests_color=red
            ts_tests_json=$(jq -nc --argjson p "$ts_passed" --argjson f "$ts_failed" --arg c "$sha" \
                '{status: "failed", passed: $p, failed: $f, commit: $c}')
        elif [ "$ts_success" != true ] || [ "$ts_tests_failed" -eq 1 ]; then
            ts_tests_value=failing
            ts_tests_color=red
            ts_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
        else
            ts_tests_value="$ts_passed passed"
            ts_tests_color=brightgreen
            ts_tests_json=$(jq -nc --argjson p "$ts_passed" --arg c "$sha" \
                '{status: "passed", passed: $p, failed: 0, commit: $c}')
        fi
    elif [ "$ts_tests_failed" -eq 1 ]; then
        ts_tests_value=failing
        ts_tests_color=red
        ts_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
    else
        echo "publish-badges: cannot read typescript test results from $ts_results" >&2
        exit 1
    fi
elif [ "$ts_tests_failed" -eq 1 ]; then
    ts_tests_value=failing
    ts_tests_color=red
    ts_tests_json=$(jq -nc --arg c "$sha" '{status: "failing", commit: $c}')
fi

details=
append_detail() {
    if [ -n "$details" ]; then
        details="$details, $1"
    else
        details="$1"
    fi
}
if [ -n "$rust_cov_value" ]; then append_detail "rust coverage $rust_cov_value"; fi
if [ -n "$rust_tests_value" ]; then append_detail "rust tests $rust_tests_value"; fi
if [ -n "$ts_cov_value" ]; then append_detail "typescript coverage $ts_cov_value"; fi
if [ -n "$ts_tests_value" ]; then append_detail "typescript tests $ts_tests_value"; fi

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
        rm -f "$work.err" "$work.push.err"
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

    # Distinguish "badges branch does not exist yet" from a remote/auth
    # error: `git ls-remote` exits 0 with empty output when the ref is
    # absent and fails loudly when the remote cannot be reached.
    badges_ref=$(git ls-remote "$remote" "refs/heads/$badges_branch")
    badges_tip=$(printf '%s\n' "$badges_ref" | awk 'NR == 1 { print $1 }')
    if [ -n "$badges_tip" ]; then
        git -c maintenance.auto=false -c gc.auto=0 fetch -q "$remote" "$badges_branch"
        add_worktree "$work" FETCH_HEAD
    else
        # First publication: an empty orphan branch.
        add_worktree "$work"
        (cd "$work" && git checkout -q --orphan "$badges_branch" && git rm -rfq . >/dev/null)
    fi

    out="$work/$branch"
    mkdir -p "$out"
    if [ -n "$rust_cov_value" ]; then
        sh "$here/badge.sh" "rust coverage" "$rust_cov_value" "$rust_cov_color" > "$out/rust-coverage.svg"
    fi
    if [ -n "$rust_tests_value" ]; then
        sh "$here/badge.sh" "rust tests" "$rust_tests_value" "$rust_tests_color" > "$out/rust-tests.svg"
    fi
    if [ -n "$ts_cov_value" ]; then
        sh "$here/badge.sh" "typescript coverage" "$ts_cov_value" "$ts_cov_color" > "$out/typescript-coverage.svg"
    fi
    if [ -n "$ts_tests_value" ]; then
        sh "$here/badge.sh" "typescript tests" "$ts_tests_value" "$ts_tests_color" > "$out/typescript-tests.svg"
    fi

    if [ -s "$out/summary.json" ] && jq -e 'type == "object"' "$out/summary.json" >/dev/null 2>&1; then
        base_summary=$(cat "$out/summary.json")
    else
        base_summary='{}'
    fi
    printf '%s' "$base_summary" | jq -c \
        --arg branch "$branch" \
        --argjson rust_cov "${rust_cov_json:-null}" \
        --argjson rust_tests "${rust_tests_json:-null}" \
        --argjson ts_cov "${ts_cov_json:-null}" \
        --argjson ts_tests "${ts_tests_json:-null}" \
        'del(.commit, .rust_lines_percent, .rust_tests_passed, .typescript_lines_percent, .typescript_tests_passed)
         | .branch = $branch
         | if $rust_cov != null then .rust_coverage = $rust_cov else . end
         | if $rust_tests != null then .rust_tests = $rust_tests else . end
         | if $ts_cov != null then .typescript_coverage = $ts_cov else . end
         | if $ts_tests != null then .typescript_tests = $ts_tests else . end' \
        > "$out/summary.json"

    git -C "$work" add -A
    if git -C "$work" diff --cached --quiet; then
        echo "badges unchanged for $branch ($details)"
        exit 0
    fi
    git -C "$work" commit -q -m "badges: $branch at $sha ($details)"
    source_is_current
    push_err="$work.push.err"
    if git -C "$work" push -q "$remote" "HEAD:refs/heads/$badges_branch" 2>"$push_err"; then
        rm -f "$push_err"
        echo "published $branch to $remote/$badges_branch ($details, commit $sha, attempt $n)"
        exit 0
    fi
    cat "$push_err" >&2
    is_non_ff=0
    if grep -Eiq 'non-fast-forward|fetch first' "$push_err"; then
        is_non_ff=1
    fi
    rm -f "$push_err"
    if [ "$is_non_ff" -eq 0 ]; then
        echo "publish-badges: push failed with a non-retryable error; giving up" >&2
        exit 1
    fi
    if [ "$n" -ge "$attempts" ]; then
        echo "publish-badges: push rejected $n times; giving up" >&2
        exit 1
    fi
    echo "publish-badges: push rejected (another publication landed); regenerating on the new tip (attempt $n/$attempts)"
    sleep "$retry_sleep"
done
