#!/bin/sh
# The two halves of the `service-nextest` step "Run the root-only local
# transport tests" in .github/workflows/ci.yml, kept here so that they have
# a self-test (node --test scripts/ci/root-transport-run.test.mjs):
#
#   sh root-transport-run.sh run LOG COMMAND [ARG...]
#       Runs COMMAND with its stdout and stderr copied to LOG and to
#       stdout, with workflow commands stopped meanwhile
#       (`::stop-commands::` with a random token), so no line a test prints
#       is read as a workflow command. The EXIT trap, and nothing else,
#       resumes them, once, on a line of its own: after COMMAND, also when
#       COMMAND or the copy fails, and when the script itself gets TERM,
#       INT or HUP (a signal to its process group, e.g. from a terminal or
#       `timeout`); on a cancel the Actions runner signals only the step's
#       shell, so the script usually gets none, and a stop it leaves ends
#       with the step. Exits with COMMAND's status, 2 when the log cannot
#       be written (its `::error::` annotation follows the resume line), or
#       143, 130 or 129 after TERM, INT or HUP.
#
#   sh root-transport-run.sh summarize LOG USERNS_STATUS RUN_STATUS LIST LIST_STATUS
#       Reads the log of that run (RUN_STATUS: its exit status) and the
#       listing of the same selection (LIST: the stdout of `cargo nextest
#       list` with the run's packages, targets and filterset and
#       `--message-format oneline --verbose`, one test per line, a test
#       outside the filterset ending in ` (skipped)`; LIST_STATUS: its exit
#       status), and appends a section to GITHUB_STEP_SUMMARY: nextest's
#       summary line, per selection (SELECTIONS below) how many of its
#       listed tests passed, the result of the user namespace probe
#       (USERNS_STATUS: the exit status of
#       `unshare --user --map-root-user --mount true` run by the step as
#       the runner user, not root: 0 allowed, anything else denied), and
#       every distinct line holding `NOTICE:` (a test that could not run
#       its check prints one). Each notice is also a `::warning::`
#       annotation, escaped (`%`, CR, LF) so that it cannot end the
#       annotation and start another workflow command. Exits 1, with an
#       `::error::` annotation and a summary line each, when RUN_STATUS or
#       LIST_STATUS is not 0; when the log or the listing is missing or
#       empty; when a listing line is not `BINARY-ID TEST ...`; when the
#       listing selects a test outside SELECTIONS, or no test of one of
#       them; when the log holds no nextest summary line; when that line
#       does not say that every test ran and passed (`N tests run: N
#       passed`, N > 0, not `M/N tests run`); when its N is not the number
#       of tests the listing selects, or its skipped count (none: 0) is not
#       the number it leaves out (the tests of the same binaries outside
#       the filterset, which nextest counts as skipped); when a selection's
#       listed tests do not all have a `PASS` (or `LEAK`) line in the log;
#       or when a notice holds one of the NOTICE_FAILS strings below; else
#       0. Only a run with none of these and no notice at all is summarized
#       as complete, and only for what it ran: the three selections (not,
#       say, the service library's own root-only tests). Usage errors exit
#       2.
#
# The selections: a binary ID and the prefix of the test names selected in
# it (none: every test). The step's filterset (.github/workflows/ci.yml)
# selects exactly these; the self-test checks that the two agree.
SELECTIONS='skyoauth-service::local_transport
skyoauth-operator::operator local_path::
skyoauth-scenarios::pg harness::socket_path_fixture::'
#
# The notices that fail the step: the step runs as root with
# SKYOAUTH_IT_PEER_USER set, on Linux on x86_64 (ubuntu-24.04), so each
# says that root-only cases did not run although they could have. One
# string per line, matched as a fixed string:
#   - `SKYOAUTH_IT_PEER_USER`: any notice naming the variable (the
#     `local_transport` tests: "SKYOAUTH_IT_PEER_USER is not set: ... was
#     NOT run").
#   - `socket path cases were NOT run: they need root`: operator
#     `local_path::socket_path_cases_match_check_socket` ("N of M socket
#     path cases were NOT run: they need root ..."); as root every case
#     runs.
#   - `the owner check needs root`: operator
#     `local_path::the_socket_must_be_the_expected_owners` ("the owner
#     check needs root: it was NOT tried"); never printed as root.
#   - `socket path cases were NOT bound by the service`:
#     `harness::socket_path_fixture::socket_path_fixture_cases_match_the_services_bind`
#     ("N of M socket path cases were NOT bound by the service: CASE
#     (REASON), ..."); as root with the peer user every case binds, and
#     each reason is root or the peer user ("an entry of root or of another
#     UID", "root's bind for another UID", "as root, the peer user").
#   - `no socket path case was bound by the service`: the same harness
#     test ("no socket path case was bound by the service: it binds on
#     Linux on x86_64, aarch64 and riscv64 only"), printed where the
#     service does not bind at all; the runner is one where it does, so
#     here it means none of the cases ran.
NOTICE_FAILS='SKYOAUTH_IT_PEER_USER
socket path cases were NOT run: they need root
the owner check needs root
socket path cases were NOT bound by the service
no socket path case was bound by the service'
# Every other notice is a warning, in the summary and as an annotation,
# and keeps the run from being called complete; these are the ones the
# selections print for a reason that does not depend on root or on the
# peer user, so they can show as root too:
#   - operator `local_path`: "CASE: this kernel follows at most N symbolic
#     links: expected refused as lookup, not accept" (the case still runs,
#     against the kernel's limit); "/tmp is not root's, sticky and
#     writable by all: the shared directory was NOT tried in it"
#     (`a_socket_in_the_systems_tmp_is_refused_as_shared`; the machine's
#     /tmp); "the working directory is too long for a relative socket path
#     that fits once absolute: that half was NOT tried".
#   - `local_transport`: "/proc/self/fd is missing ..."; "a bind without
#     /proc was NOT tested ..." (as root: `unshare` is missing, or the mount
#     namespace or the mount on /proc was denied); "a user namespace was
#     denied ...".
# The self-test feeds each NOTICE of the selections' sources through
# `summarize` and checks which of the two kinds it is.
#
# Notices and the summary line are read from files, never from a pipe into
# `grep -q`, which can stop reading early and leave the writer to die of
# SIGPIPE.
set -eu

usage() {
    echo "usage: sh $0 run LOG COMMAND [ARG...] | summarize LOG USERNS_STATUS RUN_STATUS LIST LIST_STATUS" >&2
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
    copied=0
    copy_error=
    resumed=0
    # From here on, commands resume whatever happens: `resume`, the EXIT
    # trap, is the only place that prints the resume token, and the trap
    # is never cleared, so every way out (COMMAND's status, a failed copy,
    # a signal) prints it exactly once. The leading newline ends a last
    # output line that has none, which would otherwise swallow the resume
    # token. The error for a failed copy is printed after the token, where
    # it is a live annotation. Signals are ignored while it runs, and
    # `resumed` keeps a second run from printing the token again; each
    # command is `|| :` so that, under `set -e`, a failure there cannot
    # replace the exit status.
    # shellcheck disable=SC2317 # called by the EXIT trap
    resume() {
        trap '' TERM INT HUP
        [ "$resumed" -eq 0 ] || return 0
        resumed=1
        printf '\n::%s::\n' "$token" || :
        rm -f "$status_file" || :
        if [ -n "$copy_error" ]; then
            annotate error "$copy_error" || :
        fi
    }
    # A shell killed by a signal it does not trap runs no EXIT trap, so
    # TERM, INT and HUP are trapped and exit through it, with the status a
    # shell reports for that signal (128 + its number). That applies
    # when the script itself gets TERM, INT or HUP (a signal to its process
    # group, e.g. from a terminal or `timeout`); on a cancel the Actions
    # runner signals only the step's shell, so the script usually gets
    # none, and a stop it leaves ends with the step. A signal sent to the
    # script alone, not to its process group, takes effect once COMMAND
    # and the copy have ended (POSIX defers traps while a foreground
    # command runs). Each handler ignores TERM, INT and HUP before it
    # exits, so that a second signal cannot run another handler between it
    # and `resume`.
    trap resume EXIT
    trap 'trap "" TERM INT HUP; exit 143' TERM
    trap 'trap "" TERM INT HUP; exit 130' INT
    trap 'trap "" TERM INT HUP; exit 129' HUP
    echo "::stop-commands::$token"
    { "$@" 2>&1 || echo "$?" > "$status_file"; } | tee "$log" || copied=$?
    status=$(cat "$status_file")
    # A signal that arrived while COMMAND ran has been handled by now; one
    # that arrives from here on is ignored, so it cannot kill the script
    # between this point and `resume` (it would lose the resume token) and
    # the script reports COMMAND's own status.
    trap '' TERM INT HUP
    if [ "$copied" -ne 0 ]; then
        copy_error="could not write the log $log (tee exited $copied)"
        exit 2
    fi
    exit "${status:-0}"
}

summarize() {
    [ "$#" -eq 5 ] || usage
    log=$1
    userns=$2
    status=$3
    list=$4
    listed=$5
    for n in "$userns" "$status" "$listed"; do
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
    : > "$tmp/passed"
    : > "$tmp/selections"
    line=
    run=
    skipped=0
    if [ "$status" -ne 0 ]; then
        fail "the root run exited $status"
    fi
    if [ "$listed" -ne 0 ]; then
        fail "the listing of the root run's selection (cargo nextest list) exited $listed"
    fi
    if [ ! -s "$log" ]; then
        fail "the root run left no output in $log"
    else
        grep -a 'NOTICE:' "$log" > "$tmp/all" || :
        sort -u "$tmp/all" > "$tmp/notices"
        # The tests that passed: nextest's status line for each, `PASS`
        # (`LEAK`: passed, with a leaked handle) `[time]`, the counter, and
        # the binary ID and the test's name, the last two fields.
        awk '($1 == "PASS" || $1 == "LEAK") && $2 ~ /^\[/ { print $(NF - 1), $NF }' "$log" | sort -u > "$tmp/passed"
        grep -a '^ *Summary \[' "$log" > "$tmp/summary" || :
        line=$(tail -n 1 "$tmp/summary" | sed 's/^ *//')
        if [ -z "$line" ]; then
            fail "the root run printed no nextest summary line (\`Summary [...] N tests run: ...\`)"
        else
            run=$(printf '%s\n' "$line" | sed -n 's/^Summary \[[^]]*\] \([0-9][0-9]*\) tests\{0,1\} run: .*/\1/p')
            passed=$(printf '%s\n' "$line" | sed -n 's/^Summary \[[^]]*\] [0-9][0-9]* tests\{0,1\} run: \([0-9][0-9]*\) passed.*/\1/p')
            skipped=$(printf '%s\n' "$line" | sed -n 's/.*, \([0-9][0-9]*\) skipped.*/\1/p')
            skipped=${skipped:-0}
            if [ -z "$run" ] || [ -z "$passed" ] || [ "$run" -eq 0 ] || [ "$passed" -ne "$run" ]; then
                fail "not every root-only test ran and passed: $line"
                run=
            fi
        fi
    fi
    # The listing, against SELECTIONS, as `|`-separated lines (no binary
    # ID or test name holds one): `selected|N`, `excluded|N`, one
    # `selection|BINARY-ID|PREFIX|LISTED|PASSED` each, and `bad|LINE` and
    # `outside|BINARY-ID TEST` for a listing line that is not a test and
    # for a selected test outside SELECTIONS.
    selected=
    if [ ! -s "$list" ]; then
        fail "the listing of the root run's selection is missing or empty ($list)"
    else
        printf '%s\n' "$SELECTIONS" > "$tmp/selections"
        awk -v selections="$tmp/selections" -v passed="$tmp/passed" '
            BEGIN {
                while ((getline entry < selections) > 0) {
                    n++
                    bin[n] = entry
                    sub(/ .*/, "", bin[n])
                    prefix[n] = (index(entry, " ") ? substr(entry, index(entry, " ") + 1) : "")
                }
                while ((getline entry < passed) > 0) pass[entry] = 1
            }
            function which(b, t, i) {
                for (i = 1; i <= n; i++)
                    if (b == bin[i] && substr(t, 1, length(prefix[i])) == prefix[i]) return i
                return 0
            }
            $0 !~ /^[A-Za-z0-9_-]+::[A-Za-z0-9_-]+ [^ ]/ { print "bad|" $0; next }
            $NF == "(skipped)" { excluded++; next }
            {
                all++
                i = which($1, $2)
                if (!i) { print "outside|" $1 " " $2; next }
                listed[i]++
                if (($1 " " $2) in pass) ok[i]++
            }
            END {
                print "selected|" all + 0
                print "excluded|" excluded + 0
                for (i = 1; i <= n; i++) print "selection|" bin[i] "|" prefix[i] "|" listed[i] + 0 "|" ok[i] + 0
            }' "$list" > "$tmp/listing"
        bad=$(awk '/^bad\|/ { print substr($0, 5); exit }' "$tmp/listing")
        if [ -n "$bad" ]; then
            fail "the listing holds a line that is not \`BINARY-ID TEST ...\`: $bad"
        fi
        outside=$(awk '/^outside\|/ { n++; if (n <= 5) names = names (n > 1 ? ", " : "") substr($0, 9) } END { if (n) print n " (" names (n > 5 ? ", ..." : "") ")" }' "$tmp/listing")
        if [ -n "$outside" ]; then
            fail "the filterset selects tests outside the three selections: $outside"
        fi
        selected=$(sed -n 's/^selected|//p' "$tmp/listing")
        excluded=$(sed -n 's/^excluded|//p' "$tmp/listing")
        while IFS='|' read -r kind bin prefix count ok; do
            [ "$kind" = selection ] || continue
            name="\`$bin\`${prefix:+ \`$prefix*\`}"
            if [ "$count" -eq 0 ]; then
                fail "the listing selects no test of $name"
            elif [ "$ok" -ne "$count" ]; then
                fail "$name: $ok of its $count selected tests passed"
            fi
            printf -- '- %s: %s of %s selected tests ran and passed\n' "$name" "$ok" "$count" >> "$tmp/counts"
        done < "$tmp/listing"
        if [ -n "$run" ] && { [ "$run" -ne "$selected" ] || [ "$skipped" -ne "$excluded" ]; }; then
            fail "nextest ran $run tests and skipped $skipped, but the listing selects $selected and leaves out $excluded: $line"
        fi
    fi
    if grep -q 'SKYOAUTH_IT_PEER_USER' "$tmp/notices"; then
        fail "a test printed a notice about SKYOAUTH_IT_PEER_USER although the step sets it: the root-only cross-UID checks did not run"
    fi
    printf '%s\n' "$NOTICE_FAILS" | while IFS= read -r pattern; do
        [ "$pattern" != SKYOAUTH_IT_PEER_USER ] || continue
        if grep -F -q -e "$pattern" "$tmp/notices"; then
            printf '%s\n' "$pattern"
        fi
    done > "$tmp/root-notices"
    while IFS= read -r pattern; do
        fail "a test printed a notice that its root-only cases did not run ($pattern) although the step runs as root with SKYOAUTH_IT_PEER_USER set"
    done < "$tmp/root-notices"

    if [ "$userns" -eq 0 ]; then
        probe="allowed (exit 0)"
    else
        probe="denied (exit $userns)"
    fi
    {
        echo "### Root-only tests: \`local_transport\`, operator \`local_path\`, \`harness::socket_path_fixture\`"
        echo
        if [ -n "$line" ]; then
            if [ -n "$selected" ]; then
                printf -- '- nextest: %s (the listing selects %s tests and leaves out %s of the same binaries)\n' "$line" "$selected" "$excluded"
            else
                printf -- '- nextest: %s\n' "$line"
            fi
        fi
        if [ -s "$tmp/counts" ]; then
            cat "$tmp/counts"
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
            echo "- Every selected test ran as root and passed, and none printed a notice: each root-only check of the \`local_transport\` integration target, of operator \`local_path\` and of \`harness::socket_path_fixture\` ran."
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
