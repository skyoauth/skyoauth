#!/bin/sh
# Checks what CI can prove about the README badges of this (possibly
# private) repository, after a publication for BRANCH:
#
#   1. the README at README_REF (default: BRANCH) as GitHub renders it (the
#      HTML the web page embeds)
#      carries exactly the four badge <img> elements — rust-tests.svg,
#      rust-coverage.svg, typescript-tests.svg, and
#      typescript-coverage.svg — each once, and GitHub left their
#      same-repository raw URLs in place (no Camo rewrite);
#   2. the files those URLs name, re-pointed at the directory just
#      published for BRANCH, exist on the badges branch and are served to
#      an authenticated client (the workflow token, as a signed-in browser
#      sends its session) with an SVG content type.
#
# The github.com `raw/` path itself authenticates only by browser session,
# so the fetch goes through raw.githubusercontent.com, which is where that
# path redirects a browser. Whether the images finally appear in the page
# is confirmed by a signed-in viewer of the README on `main`.
#
# README_REF is a branch or commit; a pull request passes its merge commit
# with BRANCH `main`, to check that the README it would merge still embeds
# the badges published for main.
#
# Every fetch is retried by curl (--retry 3 --retry-delay 2: timeouts, 408,
# 429 and 5xx), each attempt is limited to 20 seconds, and no retry starts
# more than 60 seconds after the first attempt (--retry-max-time 60: a
# Retry-After that would wait past that ends the retries instead of
# sleeping, which --max-time does not limit). By default (after a publication,
# and on a docs-only push to main) every problem fails the check. With
# --pull-request, a problem the pull request cannot have caused only warns
# (a `::warning::` annotation, exit 0): a transport error, 429 or 5xx that
# outlasted the retries, and a badge not published for BRANCH yet (404), so
# that a pull request that adds or renames a badge can pass; it is checked
# strictly once the merge has published it. What the README embeds, a
# README fetch answered with another error, and a badge served with a
# non-SVG type fail in both modes. When the rendered README itself cannot
# be fetched (transport error, 429 or 5xx after the retries), a pull
# request passes with a warning only if it leaves the README byte for byte
# as on the base branch: the current directory must be in the checkout of
# the merge commit README_REF (HEAD must be that commit, with exactly two
# parents, both fetched: fetch-depth 2), every README path in HEAD and
# HEAD^1 must be a regular file (no symbolic link, also not for .github/
# or docs/), and `git diff --quiet HEAD^1 HEAD` must find no change to any
# file GitHub could render as the README (README* at the top level, in
# .github/ and in docs/, in any case). The README is then the one already
# verified on main, and the four badge files are checked as in 2. A pull
# request that changes the README fails (re-run the job once the API
# answers again), as does a missing parent commit or any git error. No
# Markdown is parsed.
#
#   GH_TOKEN=... scripts/ci/verify-badges-render.sh [--pull-request] OWNER/REPO BRANCH [README_REF]
set -eu
usage() {
    echo "usage: verify-badges-render.sh [--pull-request] OWNER/REPO BRANCH [README_REF]" >&2
    exit 2
}
pull_request=0
case ${1-} in
    --pull-request) pull_request=1; shift ;;
    -*) usage ;;
esac
case $# in
    2 | 3) ;;
    *) usage ;;
esac
repo=$1
branch=$2
readme_ref=${3:-$branch}
: "${GH_TOKEN:?}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# fetch OUT URL [CURL-OPTION...]: sets code, ctype and transient (1 for a
# transport error, 429 or 5xx after curl's retries).
fetch() {
    fetch_out=$1
    fetch_url=$2
    shift 2
    rc=0
    meta=$(curl -sS --retry 3 --retry-delay 2 --retry-max-time 60 --max-time 20 -o "$fetch_out" \
        -w '%{http_code} %{content_type}' "$@" "$fetch_url") || rc=$?
    code=${meta%% *}
    ctype=${meta#* }
    [ "$ctype" != "$meta" ] || ctype=
    transient=0
    if [ "$rc" -ne 0 ]; then
        transient=1
        what="transport error, curl exit $rc"
    else
        case $code in
            429 | 5[0-9][0-9]) transient=1 ;;
        esac
        what="HTTP $code${ctype:+ $ctype}"
    fi
}

# problem MESSAGE: fails the check.
problem() {
    echo "verify-badges-render: $1" >&2
    status=1
}

# transient_problem MESSAGE: only a warning with --pull-request.
transient_problem() {
    if [ "$pull_request" -eq 1 ]; then
        echo "::warning::verify-badges-render: $1"
    else
        problem "$1"
    fi
}

status=0
readme_api="https://api.github.com/repos/$repo/readme?ref=$readme_ref"
fetch "$tmp/readme.html" "$readme_api" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github.html+json"
if [ "$transient" -eq 1 ] && [ "$pull_request" -eq 0 ]; then
    problem "could not fetch the rendered README at $readme_ref ($what); nothing was checked"
    exit 1
elif [ "$transient" -eq 1 ]; then
    # The fallback (see the top): pass only for an unchanged README.
    unavailable="could not fetch the rendered README at $readme_ref ($what)"
    if ! git rev-parse -q --verify 'HEAD^1^{commit}' >/dev/null 2>&1; then
        problem "$unavailable, and cannot compare the README with the base branch: no parent commit of HEAD in $(pwd) (not a git checkout, or a shallow one; the job checks out with fetch-depth 2)"
        exit 1
    fi
    # HEAD^1 is the base tip only in a pull request's merge commit, which
    # has exactly two parents (the base tip and the pull request's head).
    parents=$(git show -s --format=%P HEAD 2>/dev/null | awk '{ print NF }')
    if [ "$parents" != 2 ] || ! git rev-parse -q --verify 'HEAD^2^{commit}' >/dev/null 2>&1; then
        problem "$unavailable, and HEAD is not a merge commit with two parents (${parents:-unknown} parents), so HEAD^1 is not known to be the base tip"
        exit 1
    fi
    head=$(git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null) || head=
    ref=$(git rev-parse -q --verify "$readme_ref^{commit}" 2>/dev/null) || ref=
    if [ -z "$ref" ] || [ "$head" != "$ref" ]; then
        problem "$unavailable, and the current directory is not a checkout of $readme_ref (HEAD is ${head:-unknown}, $readme_ref is ${ref:-no commit here}), so its README cannot stand in for the one being checked"
        exit 1
    fi
    # Only regular files: a symbolic link (or a submodule) at a README
    # path, or in place of .github/ or docs/, can change what GitHub
    # renders without any change to the README paths themselves. Read from
    # the commits, not the working tree.
    if ! trees=$(git ls-tree -r --full-tree HEAD && git ls-tree -r --full-tree 'HEAD^1'); then
        problem "$unavailable, and git could not list the files of HEAD and HEAD^1"
        exit 1
    fi
    odd=$(printf '%s\n' "$trees" | awk -F '\t' '{
        split($1, f, " ")
        p = tolower($2)
        sub(/^"/, "", p)
    }
    (p ~ /^(\.github\/|docs\/)?readme/ || p == ".github" || p == "docs") && f[1] != "100644" && f[1] != "100755" {
        print $2 " (mode " f[1] ")"
    }' | sort -u)
    if [ -n "$odd" ]; then
        problem "$unavailable, and a README path is not a regular file in HEAD or HEAD^1, so an unchanged README proves nothing: $(printf '%s' "$odd" | tr '\n' ' ')"
        exit 1
    fi
    rc=0
    git diff --quiet 'HEAD^1' HEAD -- ':(top,icase)README*' ':(top,icase).github/README*' ':(top,icase)docs/README*' || rc=$?
    case $rc in
        0) ;;
        1)
            problem "$unavailable, and this pull request changes the README, which cannot be checked without it; re-run this job once the GitHub API answers again"
            exit 1 ;;
        *)
            problem "$unavailable, and git could not compare the README with the base branch (git diff exit $rc)"
            exit 1 ;;
    esac
    echo "::warning::verify-badges-render: $unavailable; the README is unchanged from the base branch, so only the published badge files are checked"
    readme="unchanged README"
    urls=
    for file in rust-tests rust-coverage typescript-tests typescript-coverage; do
        urls="$urls https://github.com/$repo/raw/badges/main/$file.svg"
    done
else
    if [ "$code" != 200 ]; then
        problem "could not fetch the rendered README at $readme_ref: $readme_api answered $what"
        exit 1
    fi
    readme="rendered README"
    urls=$(grep -o '<img[^>]*>' "$tmp/readme.html" | grep -E 'coverage\.svg|tests\.svg' \
        | sed -E 's/^<img[^>]*[[:space:]]src="([^"]*)".*/\1/' || true)
    if [ -z "$urls" ]; then
        echo "verify-badges-render: no badge <img> in the rendered README:" >&2
        grep -o '<img[^>]*>' "$tmp/readme.html" >&2 || true
        exit 1
    fi
fi
seen_rust_tests=0
seen_rust_coverage=0
seen_typescript_tests=0
seen_typescript_coverage=0
for url in $urls; do
    url=$(printf '%s' "$url" | sed 's|&amp;|\&|g')
    case "$url" in
        https://github.com/"$repo"/raw/badges/main/rust-tests.svg)
            seen_rust_tests=$((seen_rust_tests + 1)) ;;
        https://github.com/"$repo"/raw/badges/main/rust-coverage.svg)
            seen_rust_coverage=$((seen_rust_coverage + 1)) ;;
        https://github.com/"$repo"/raw/badges/main/typescript-tests.svg)
            seen_typescript_tests=$((seen_typescript_tests + 1)) ;;
        https://github.com/"$repo"/raw/badges/main/typescript-coverage.svg)
            seen_typescript_coverage=$((seen_typescript_coverage + 1)) ;;
        *)
            problem "unexpected badge URL in the $readme: $url"
            continue ;;
    esac
    file=${url##*/badges/main/}
    raw="https://raw.githubusercontent.com/$repo/badges/$branch/$file"
    fetch "$tmp/badge" "$raw" -L -H "Authorization: token $GH_TOKEN"
    echo "README embeds $url"
    echo "  published file $raw -> ${code:-000} ${ctype:-?}"
    if [ "$transient" -eq 1 ]; then
        transient_problem "could not fetch $raw ($what)"
    elif [ "$code" = 404 ] && [ "$pull_request" -eq 1 ]; then
        echo "::warning::verify-badges-render: $file is not published for $branch yet (HTTP 404); it is checked once the merge publishes it"
    else
        case "$code:$ctype" in
            200:*svg*) ;;
            *) problem "$file is not served as SVG ($what)" ;;
        esac
    fi
done
check_badge() {
    badge=$1
    n=$2
    if [ "$n" -eq 0 ]; then
        problem "the $readme does not embed badges/main/$badge.svg"
    elif [ "$n" -gt 1 ]; then
        problem "badges/main/$badge.svg is embedded more than once ($n)"
    fi
}
check_badge rust-tests "$seen_rust_tests"
check_badge rust-coverage "$seen_rust_coverage"
check_badge typescript-tests "$seen_typescript_tests"
check_badge typescript-coverage "$seen_typescript_coverage"
if [ "$status" -ne 0 ]; then
    echo "verify-badges-render: the README badges do not verify (see above)" >&2
fi
exit "$status"
