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
#   DOWNLOADS            one line `<job>=<artifact name>` per leg job of
#                        the workflow: the leg artifact that job uploaded,
#                        as the job itself named it in its `junit-artifact`
#                        output, or nothing after `=` when it uploaded none
#   DOWNLOAD_DIR         where the workflow downloaded each named artifact
#                        by its name: DOWNLOAD_DIR/<job>/, which then holds
#                        the artifact's files directly
#   ARTIFACTS            the artifacts directory this script builds for the
#                        reporter: ARTIFACTS/GITHUB_RUN_ID/<artifact name>/
#                        and ARTIFACTS/GITHUB_RUN_ID/run.json; it must not
#                        hold that run directory yet
#   REPORT_JSON          where the JSON result is written
#   GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_WORKFLOW, GITHUB_EVENT_NAME,
#   GITHUB_HEAD_REF, GITHUB_REF_NAME,
#   GITHUB_STEP_SUMMARY  set by the runner
#
# run.json: the reporter binds a run directory to the commit through
# ARTIFACTS/GITHUB_RUN_ID/run.json, the fields that `gh run view RUN_ID
# --json databaseId,headSha,attempt,workflowName,event,headBranch` gives.
# For the running attempt they are known without asking the API
# (databaseId GITHUB_RUN_ID, headSha COMMIT, as gh gives the PR head for a
# pull_request run, attempt GITHUB_RUN_ATTEMPT, the latest so far,
# workflowName GITHUB_WORKFLOW, event GITHUB_EVENT_NAME, and headBranch
# GITHUB_HEAD_REF, the PR's head branch, in a pull_request run, else
# GITHUB_REF_NAME), so this script writes the file and the job needs no
# token beyond `contents: read`. The reporter checks the first four; event
# and headBranch are written for the join of every run of a commit, which
# must accept only runs of trusted events (layout §3 "Result join", §6
# "Still open", item 6), and the reporter does not read them yet. An
# existing run.json is an error, not overwritten.
#
# Leg artifacts: the artifact name, and so the run attempt the reporter
# reads from it, comes only from the job that uploaded the artifact. This
# script never derives it from the files or from GITHUB_RUN_ATTEMPT, which a
# re-run of this job alone would make the wrong attempt. Before using a name
# as a path it must match junit-[a-z0-9_-]+-attempt-N. The download must
# hold exactly the regular file `leg` and, when the tests ran, the regular
# file `junit.xml`, with nothing else: a directory, a symbolic link, a
# run.json or any other entry is an input error, as is a `leg` that is not
# one line naming a leg string whose leg id is the one in the name and
# whose job (the leg string up to its `/`) is the job of that DOWNLOADS
# line. Checked without following links; the two files are then moved (not
# copied) to ARTIFACTS/GITHUB_RUN_ID/<artifact name>/, and only then is
# run.json written. A leg job that uploaded nothing (an empty name) gets a
# warning and its legs are not run. The workflow runs this script only when
# every download succeeded.
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
# A missing or malformed variable, an existing run directory or a download
# that breaks the rules above is an error of this script: exit 2 before the
# reporter runs.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

# printf, not echo: dash's echo would turn a backslash escape in a message
# into the byte it names.
usage() {
    printf '::error title=Conformance report::report-conformance-ci: %s\n' "$1"
    exit 2
}
# A file or directory name found in the download directory, as a message
# may show it: A-Za-z0-9._- as they are, every other byte as `?`, so that a
# name an artifact chose cannot end the line and start a workflow command
# of its own, or carry a control character.
shown() {
    printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._-' '?'
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
event=${GITHUB_EVENT_NAME:-}
case $event in
    '' | *[!a-z_]*) usage "GITHUB_EVENT_NAME must be an event name (a-z and _), not '$event'" ;;
esac
head_branch=${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-}}
[ -n "$head_branch" ] || usage "GITHUB_HEAD_REF and GITHUB_REF_NAME are both unset or empty"
download_dir=${DOWNLOAD_DIR:-}
[ -n "$download_dir" ] || usage "DOWNLOAD_DIR is not set"
downloads=${DOWNLOADS:-}

# The run directory is new, so nothing in it predates the moves below; it
# exists even when no leg artifact was downloaded, whose legs are then not
# run.
run_dir=$artifacts/$run_id
if [ -e "$run_dir" ] || [ -L "$run_dir" ]; then
    usage "$run_dir exists already"
fi
mkdir -p "$artifacts"
mkdir "$run_dir" || usage "cannot create $run_dir"
if [ -L "$download_dir" ]; then usage "$download_dir is a symbolic link"; fi

# One line per leg job: check the named download and move its files into
# the run directory under that name.
jobs=' '
listed=
while IFS= read -r line; do
    [ -n "$line" ] || continue
    job=${line%%=*}
    name=${line#*=}
    [ "$job" != "$line" ] || usage "DOWNLOADS line '$line' is not <job>=<artifact name>"
    case $job in
        '' | *[!a-z0-9-]*) usage "DOWNLOADS line '$line': '$job' is not a job id (a-z, 0-9 and -)" ;;
    esac
    case $jobs in
        *" $job "*) usage "DOWNLOADS names job $job twice" ;;
    esac
    jobs="$jobs$job "
    stage=$download_dir/$job
    if [ -z "$name" ]; then
        if [ -e "$stage" ] || [ -L "$stage" ]; then
            usage "$stage exists, but job $job named no leg artifact"
        fi
        echo "::warning title=Conformance report::Job $job uploaded no leg artifact in this run (it stopped before its upload, or did not run), so its legs are not run here."
        listed="$listed- \`$job\`: no leg artifact
"
        continue
    fi
    if ! printf '%s\n' "$name" | LC_ALL=C grep -Eqx 'junit-[a-z0-9_-]+-attempt-[1-9][0-9]*'; then
        usage "DOWNLOADS line '$line': '$name' is not a leg artifact name junit-<leg id>-attempt-N"
    fi
    if [ -L "$stage" ] || [ ! -d "$stage" ]; then
        usage "$stage: the download of $name is not a directory"
    fi
    # Every entry, dot files included, without following links.
    for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
        if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then continue; fi
        base=${entry##*/}
        case $base in
            leg | junit.xml) ;;
            *) usage "$name holds '$(shown "$base")'; a leg artifact holds only the files leg and junit.xml, at its top" ;;
        esac
        if [ -L "$entry" ] || [ ! -f "$entry" ]; then
            usage "$name/$(shown "$base") is not a regular file"
        fi
    done
    [ -f "$stage/leg" ] || usage "$name has no leg file"
    size=$(wc -c < "$stage/leg")
    [ "$size" -le 256 ] || usage "$name/leg holds $size bytes, more than one leg string"
    leg=$(cat "$stage/leg")
    if [ "$(wc -l < "$stage/leg")" -ne 1 ] || [ "$size" -ne $((${#leg} + 1)) ] ||
        ! printf '%s\n' "$leg" | LC_ALL=C grep -Eqx '[a-z0-9-]+(/[a-z0-9_]+)?'; then
        usage "$name/leg is not one line holding a leg string"
    fi
    id=$(printf '%s' "$leg" | tr / -)
    attempt=${name#"junit-$id-attempt-"}
    case $attempt in
        '' | *[!0-9]*) usage "$name/leg names leg $leg, whose artifact is junit-$id-attempt-N" ;;
    esac
    # The leg is one of this job's legs: a line naming another job's
    # artifact would report that job's results as this job's download.
    leg_job=${leg%%/*}
    [ "$leg_job" = "$job" ] || usage "$name/leg names leg $leg of job $leg_job, but DOWNLOADS names $name for job $job"
    mkdir "$run_dir/$name" || usage "cannot create $run_dir/$name"
    mv -- "$stage/leg" "$run_dir/$name/leg" || usage "cannot move $name/leg"
    if [ -e "$stage/junit.xml" ]; then
        mv -- "$stage/junit.xml" "$run_dir/$name/junit.xml" || usage "cannot move $name/junit.xml"
    fi
    rmdir -- "$stage" || usage "cannot remove $stage after moving its files"
    listed="$listed- \`$job\`: \`$name\`
"
done <<EOF
$downloads
EOF
[ "$jobs" != ' ' ] || usage "DOWNLOADS names no leg job"
# Nothing else was downloaded: every job's directory is gone.
if [ -d "$download_dir" ]; then
    for entry in "$download_dir"/* "$download_dir"/.[!.]* "$download_dir"/..?*; do
        if [ -e "$entry" ] || [ -L "$entry" ]; then usage "$download_dir holds '$(shown "${entry##*/}")', which no line of DOWNLOADS names"; fi
    done
fi

RUN_JSON="$run_dir/run.json" COMMIT=$commit EVENT=$event HEAD_BRANCH=$head_branch node -e '
const e = process.env;
const run = { databaseId: Number(e.GITHUB_RUN_ID), headSha: e.COMMIT, attempt: Number(e.GITHUB_RUN_ATTEMPT), workflowName: e.GITHUB_WORKFLOW, event: e.EVENT, headBranch: e.HEAD_BRANCH };
require("node:fs").writeFileSync(e.RUN_JSON, JSON.stringify(run) + "\n", { flag: "wx" });
' || usage "cannot write $run_dir/run.json"

{
    echo "> **Informational.** This conformance report covers only the leg artifacts of this workflow run (run $run_id) that its leg jobs named, one per leg job from the attempt that job last ran in; it does not read earlier attempts of a leg job or the other runs for this commit, and judges no milestone gate. Stages without a result here are not run."
    echo ">"
    printf '%s' "$listed" | sed 's/^/> /'
    if [ "$event" = pull_request ]; then
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
