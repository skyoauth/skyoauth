#!/bin/sh
# Runs report-conformance.mjs for the informational `conformance-report` CI
# job (docs/testing/conformance-layout.md §3 "Leg artifacts"). It judges the
# leg artifacts of the current workflow run only, not every run for the
# commit, and no milestone gate: it passes no --require-milestone, no
# --require-history and no --allow-commit-mismatch. Everything comes from
# the environment, which the workflow sets (no expression is interpolated
# into the script):
#
#   COMMIT               the judged commit, checked out at the repository
#                        root (the reporter's default --root): the PR head
#                        for a pull_request run, else GITHUB_SHA
#   ARTIFACTS            the artifacts directory; the job has downloaded the
#                        run's leg artifacts into
#                        ARTIFACTS/GITHUB_RUN_ID/<artifact name>/
#   REPORT_JSON          where the JSON result is written
#   GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_WORKFLOW, GITHUB_EVENT_NAME,
#   GITHUB_STEP_SUMMARY  set by the runner
#
# run.json: the reporter binds a run directory to the commit through
# ARTIFACTS/GITHUB_RUN_ID/run.json, the four fields that `gh run view RUN_ID
# --json databaseId,headSha,attempt,workflowName` gives. For the running
# attempt they are known without asking the API (databaseId GITHUB_RUN_ID,
# headSha COMMIT, as gh gives the PR head for a pull_request run, attempt
# GITHUB_RUN_ATTEMPT, the latest so far, and workflowName GITHUB_WORKFLOW),
# so this script writes the file and the job needs no token beyond
# `contents: read`. An existing run.json is an error, not overwritten.
#
# Exit status: informational, so only a reporter error fails the job.
#   reporter 0  no implemented stage has a failed pair (stages that are not
#               run or planned never fail it)                        -> 0
#   reporter 1  an implemented stage has a failed (unwaived) pair     -> 0,
#               with a warning annotation: the failing test already fails
#               its own leg job, and this job judges no gate
#   reporter 2  usage, registry or input errors (no report, or an
#               untrusted one), or an internal error (a crash)        -> 2
#   any other   the reporter died (a signal, out of memory)           -> it
# A missing or malformed variable, or an existing run.json, is a usage
# error of this script: exit 2 before the reporter runs.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

usage() {
    echo "::error title=Conformance report::report-conformance-ci: $1"
    exit 2
}
positive() {
    case $2 in
        '' | 0* | *[!0-9]*) usage "$1 must be a positive integer, not '$2'" ;;
    esac
}

commit=${COMMIT:-}
case $commit in
    *[!0-9a-f]*) usage "COMMIT must be a full 40-character lowercase hex SHA, not '$commit'" ;;
esac
[ "${#commit}" -eq 40 ] || usage "COMMIT must be a full 40-character lowercase hex SHA, not '$commit'"
artifacts=${ARTIFACTS:-}
[ -n "$artifacts" ] || usage "ARTIFACTS is not set"
report_json=${REPORT_JSON:-}
[ -n "$report_json" ] || usage "REPORT_JSON is not set"
summary=${GITHUB_STEP_SUMMARY:-}
[ -n "$summary" ] || usage "GITHUB_STEP_SUMMARY is not set"
run_id=${GITHUB_RUN_ID:-}
positive GITHUB_RUN_ID "$run_id"
run_attempt=${GITHUB_RUN_ATTEMPT:-}
positive GITHUB_RUN_ATTEMPT "$run_attempt"
[ -n "${GITHUB_WORKFLOW:-}" ] || usage "GITHUB_WORKFLOW is not set"

# The run directory exists even when no leg artifact was downloaded (a leg
# job that stopped before its upload): its legs are then not run.
mkdir -p "$artifacts/$run_id"
RUN_JSON="$artifacts/$run_id/run.json" COMMIT=$commit node -e '
const e = process.env;
const run = { databaseId: Number(e.GITHUB_RUN_ID), headSha: e.COMMIT, attempt: Number(e.GITHUB_RUN_ATTEMPT), workflowName: e.GITHUB_WORKFLOW };
require("node:fs").writeFileSync(e.RUN_JSON, JSON.stringify(run) + "\n", { flag: "wx" });
' || usage "cannot write $artifacts/$run_id/run.json (does it exist already?)"

{
    echo "> **Informational.** This conformance report covers only the leg artifacts of this workflow run (run $run_id, attempts 1 to $run_attempt), not the other runs for this commit, and judges no milestone gate. Stages without a result here are not run."
    if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
        echo "> In a pull request run the judged commit is the PR head, while the leg jobs tested its merge with the base branch."
    fi
    echo
} >> "$summary"

status=0
node "$here/report-conformance.mjs" --commit "$commit" --artifacts "$artifacts" \
    --json "$report_json" --summary "$summary" || status=$?

case $status in
    0) ;;
    1)
        echo "::warning title=Conformance report::An implemented conformance stage has a failed result in this run (see the job summary). This job is informational and judges no gate; the failing test fails its own job."
        ;;
    2)
        echo "::error title=Conformance report::The conformance reporter found usage, registry or input errors, or crashed (exit 2); the report is missing or cannot be trusted. See the log above."
        exit 2
        ;;
    *)
        echo "::error title=Conformance report::The conformance reporter died with exit status $status."
        exit "$status"
        ;;
esac
