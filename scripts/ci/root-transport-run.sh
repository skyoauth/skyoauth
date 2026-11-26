#!/bin/sh
# The two halves of the `service-nextest` step "Run the root-only local
# transport tests" in .github/workflows/ci.yml, kept here so that they have
# a self-test (node --test scripts/ci/root-transport-run.test.mjs):
#
#   sh root-transport-run.sh run LOG COMMAND [ARG...]
#       Runs COMMAND with its stdout and stderr copied to LOG and to
#       stdout, with workflow commands stopped meanwhile
#       (`::stop-commands::` with a random token, resumed afterwards on a
#       line of its own, also when COMMAND or the copy fails), so no line
#       a test prints is read as a workflow command. Exits with COMMAND's
#       status, or 2 when the log cannot be written.
#
#   sh root-transport-run.sh summarize LOG USERNS_STATUS RUN_STATUS
#       Reads the log of that run (RUN_STATUS: its exit status) and appends
#       a section to GITHUB_STEP_SUMMARY: nextest's summary line, the result
#       of the user
#       namespace probe (USERNS_STATUS: the exit status of
#       `unshare --user --map-root-user --mount true` run by the step as
#       the runner user, not root: 0 allowed, anything else denied), and
#       every distinct line holding `NOTICE:` (a test that could not run
#       its check prints one). Each notice is also a `::warning::`
#       annotation, escaped (`%`, CR, LF) so that it cannot end the
#       annotation and start another workflow command. Exits 1, with an
#       `::error::` annotation and a summary line each, when RUN_STATUS is
#       not 0, when the log is missing or empty, when it holds no nextest
#       summary line, when that line does not say every test ran and passed
#       (`N tests run: N passed`, N > 0, nothing skipped, not
#       `M/N tests run`), or when a notice names SKYOAUTH_IT_PEER_USER (the
#       step sets it, so such a notice means the cross-UID checks did not
#       run); else 0. Only a run with none of these and no notice at all is
#       summarized as complete, and only for what it ran: the
#       `local_transport` integration test target (not the library's own
#       tests). Usage errors exit 2.
#
# Notices and the summary line are read from files, never from a pipe into
# `grep -q`, which can stop reading early and leave the writer to die of
# SIGPIPE.
set -eu

usage() {
    echo "usage: sh $0 run LOG COMMAND [ARG...] | summarize LOG USERNS_STATUS RUN_STATUS" >&2
    exit 2
}

# annotate LEVEL MESSAGE: one workflow command, the message escaped as the
# runner unescapes it (`%` first, then CR and LF).
annotate() {
    printf '%s\n' "$2" | awk -v level="$1" '
        { gsub(/%/, "%25"); gsub(/\r/, "%0D"); message = (NR > 1 ? message "%0A" : "") $0 }
        END { print "::" level "::" message }'
}

run() {
    [ "$#" -ge 2 ] || usage
    log=$1
    shift
    token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    case $token in
        ????????????????????????????????) ;;
        *) annotate error "could not read a random token from /dev/urandom"; exit 2 ;;
    esac
    status_file=$(mktemp)
    # From here on, commands resume whatever happens. The leading newline
    # ends a last output line that has none, which would otherwise swallow
    # the resume token.
    trap 'printf "\n::%s::\n" "$token"; rm -f "$status_file"' EXIT
    echo "::stop-commands::$token"
    copied=0
    { "$@" 2>&1 || echo "$?" > "$status_file"; } | tee "$log" || copied=$?
    status=$(cat "$status_file")
    trap - EXIT
    printf '\n::%s::\n' "$token"
    rm -f "$status_file"
    if [ "$copied" -ne 0 ]; then
        annotate error "could not write the log $log (tee exited $copied)"
        exit 2
    fi
    exit "${status:-0}"
}

summarize() {
    [ "$#" -eq 3 ] || usage
    log=$1
    userns=$2
    status=$3
    for n in "$userns" "$status"; do
        case $n in '' | *[!0-9]*) usage ;; esac
    done
    # Byte order for sort, whatever the runner's locale (not for `run`: the
    # tests keep the runner's).
    LC_ALL=C
    export LC_ALL
    summary=${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is not set}
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    failed=0
    fail() {
        annotate error "$1"
        printf -- '- **Failed:** %s\n' "$1" >> "$tmp/failures"
        failed=1
    }

    : > "$tmp/notices"
    line=
    if [ "$status" -ne 0 ]; then
        fail "the root run exited $status"
    fi
    if [ ! -s "$log" ]; then
        fail "the root run left no output in $log"
    else
        grep -a 'NOTICE:' "$log" > "$tmp/all" || :
        sort -u "$tmp/all" > "$tmp/notices"
        grep -a '^ *Summary \[' "$log" > "$tmp/summary" || :
        line=$(tail -n 1 "$tmp/summary" | sed 's/^ *//')
        if [ -z "$line" ]; then
            fail "the root run printed no nextest summary line (\`Summary [...] N tests run: ...\`)"
        else
            run=$(printf '%s\n' "$line" | sed -n 's/^Summary \[[^]]*\] \([0-9][0-9]*\) tests\{0,1\} run: .*/\1/p')
            passed=$(printf '%s\n' "$line" | sed -n 's/^Summary \[[^]]*\] [0-9][0-9]* tests\{0,1\} run: \([0-9][0-9]*\) passed.*/\1/p')
            skipped=$(printf '%s\n' "$line" | sed -n 's/.*, \([0-9][0-9]*\) skipped.*/\1/p')
            if [ -z "$run" ] || [ -z "$passed" ] || [ "$run" -eq 0 ] || [ "$passed" -ne "$run" ] || [ "${skipped:-0}" -ne 0 ]; then
                fail "not every root-only test ran and passed: $line"
            fi
        fi
    fi
    if grep -q 'SKYOAUTH_IT_PEER_USER' "$tmp/notices"; then
        fail "a test printed a notice about SKYOAUTH_IT_PEER_USER although the step sets it: the root-only cross-UID checks did not run"
    fi

    if [ "$userns" -eq 0 ]; then
        probe="allowed (exit 0)"
    else
        probe="denied (exit $userns)"
    fi
    {
        echo "### Root-only local transport tests"
        echo
        if [ -n "$line" ]; then
            printf -- '- nextest: %s\n' "$line"
        fi
        # shellcheck disable=SC2016 # literal backticks: Markdown code
        printf -- '- User namespaces for the runner user (not root; `unshare --user --map-root-user --mount true`): %s\n' "$probe"
        if [ -s "$tmp/failures" ]; then
            cat "$tmp/failures"
        fi
        if [ -s "$tmp/notices" ]; then
            echo
            echo "Notices printed by tests (a test that could not run its check):"
            echo
            sed 's/^/- /' "$tmp/notices"
        elif [ "$failed" -eq 0 ]; then
            echo "- Every test of the \`local_transport\` integration target ran as root and passed, and none printed a notice: each of its root-only checks ran."
        fi
    } >> "$summary"
    awk '{ gsub(/%/, "%25"); gsub(/\r/, "%0D"); print "::warning::" $0 }' "$tmp/notices"
    return "$failed"
}

[ "$#" -ge 1 ] || usage
command=$1
shift
case $command in
    run) run "$@" ;;
    summarize) summarize "$@" ;;
    *) usage ;;
esac
