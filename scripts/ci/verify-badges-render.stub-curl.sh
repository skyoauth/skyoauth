#!/bin/sh
# Stub curl for verify-badges-render.test.mjs, which installs it as `curl`
# first on PATH, so the test needs no network. CURL_STUB_DIR holds its
# rules file, readme.html and the logs it appends to: calls.log (the
# arguments of each call) and attempts.log (`URL RESPONSE` per attempt).
#
# Rules are lines `URL-SUBSTRING RESPONSE...`. The first rule whose
# substring the URL contains answers it, each attempt taking that rule's
# next response; the last one repeats. A response is
# `CODE[:CONTENT-TYPE[:BODY]]` (BODY `readme` sends readme.html, else the
# body is a small one fitting the type), or `xN`: a transport error, code
# 000 and exit status N. Like curl (checked against curl 8.5.0), the stub
# retries 408, 429, 500, 502, 503, 504, a failed name resolution (x6) and
# a timeout (x28), and no other transport error, up to --retry times; it
# does not sleep. It honours -o, -w with %{http_code}
# and %{content_type}, -D and -f (exit 22 from HTTP 400 up), and ignores
# every other option.
set -eu
dir=${CURL_STUB_DIR:?}
printf '%s\n' "$*" >> "$dir/calls.log"
out=/dev/stdout
fmt=
headers=
fail_on_error=0
url=
retry=0
while [ $# -gt 0 ]; do
    case $1 in
        -o) out=$2; shift 2 ;;
        -w) fmt=$2; shift 2 ;;
        -D) headers=$2; shift 2 ;;
        --retry) retry=$2; shift 2 ;;
        -H | --retry-delay | --retry-max-time | --max-time) shift 2 ;;
        -f | --fail) fail_on_error=1; shift ;;
        -*f*) case $1 in --*) ;; *) fail_on_error=1 ;; esac; shift ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
[ "$out" = - ] && out=/dev/stdout
[ "$headers" = - ] && headers=/dev/stdout

idx=0
responses=
while read -r sub rest; do
    idx=$((idx + 1))
    case $url in
        *"$sub"*) responses=$rest; break ;;
    esac
done < "$dir/rules"
if [ -z "$responses" ]; then
    echo "stub curl: no rule for $url" >&2
    exit 99
fi

resp=
attempt=0
while :; do
    n=$(cat "$dir/count.$idx" 2>/dev/null || echo 0)
    echo $((n + 1)) > "$dir/count.$idx"
    # Word splitting of the rule's responses is intended.
    # shellcheck disable=SC2086
    set -- $responses
    i=$((n + 1))
    if [ "$i" -gt "$#" ]; then i=$#; fi
    eval "resp=\${$i}"
    echo "$url $resp" >> "$dir/attempts.log"
    case $resp in
        408* | 429* | 500* | 502* | 503* | 504* | x6 | x28) retryable=1 ;;
        *) retryable=0 ;;
    esac
    if [ "$retryable" = 1 ] && [ "$attempt" -lt "$retry" ]; then
        attempt=$((attempt + 1))
        continue
    fi
    break
done

status=0
ctype=
case $resp in
    x*)
        code=000
        status=${resp#x}
        echo "curl: ($status) stub transport error" >&2 ;;
    *)
        code=${resp%%:*}
        body=
        case $resp in
            *:*:*) ctype=${resp#*:}; body=${ctype#*:}; ctype=${ctype%%:*} ;;
            *:*) ctype=${resp#*:} ;;
        esac
        if [ -n "$headers" ]; then
            printf 'HTTP/2 %s\r\n' "$code" >> "$headers"
            [ -z "$ctype" ] || printf 'content-type: %s\r\n' "$ctype" >> "$headers"
            printf '\r\n' >> "$headers"
        fi
        if [ "$fail_on_error" = 1 ] && [ "$code" -ge 400 ]; then
            echo "curl: (22) The requested URL returned error: $code" >&2
            status=22
        elif [ "$body" = readme ]; then
            cat "$dir/readme.html" > "$out"
        else
            case $ctype in
                *svg*) printf '<svg xmlns="http://www.w3.org/2000/svg"/>' > "$out" ;;
                *) printf 'stub body\n' > "$out" ;;
            esac
        fi ;;
esac
CODE=$code CTYPE=$ctype FMT=$fmt awk 'BEGIN {
    f = ENVIRON["FMT"]
    while ((i = index(f, "%{http_code}")) > 0) f = substr(f, 1, i - 1) ENVIRON["CODE"] substr(f, i + 12)
    while ((i = index(f, "%{content_type}")) > 0) f = substr(f, 1, i - 1) ENVIRON["CTYPE"] substr(f, i + 15)
    printf "%s", f
}'
exit "$status"
