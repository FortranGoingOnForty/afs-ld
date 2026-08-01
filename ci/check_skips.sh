#!/bin/sh
# Validate afs-ld's machine-readable integration-test skip records.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <test-log> <macos|linux>" >&2
    exit 2
fi

log=$1
profile=$2

if [ ! -r "$log" ]; then
    echo "check_skips: cannot read test log '$log'" >&2
    exit 2
fi

case "$profile" in
macos | linux)
    ;;
*)
    echo "check_skips: unknown profile '$profile' (macos | linux)" >&2
    exit 2
    ;;
esac

if grep -Fiq 'skipping:' "$log"; then
    echo "check_skips: unstructured passing skip(s) found:" >&2
    grep -Fin 'skipping:' "$log" >&2 || true
    exit 1
fi

markers=$(grep -c '^HARNESS_SKIP ' "$log" || true)
if [ "$markers" -eq 0 ]; then
    echo "check_skips: no HARNESS_SKIP records; output was captured or platform suites vanished" >&2
    exit 1
fi

records=$(grep -Ec '^HARNESS_SKIP suite=[^[:space:]]+ test=[^[:space:]]+ count=[1-9][0-9]* reason=".*"$' "$log" || true)
if [ "$records" -ne "$markers" ]; then
    echo "check_skips: malformed HARNESS_SKIP record(s): found $markers marker(s), parsed $records" >&2
    grep -n '^HARNESS_SKIP ' "$log" >&2 || true
    exit 1
fi

if grep -Ei '^HARNESS_SKIP .*reason="[^"]*(failed|failure|could not)' "$log" >/dev/null; then
    echo "check_skips: post-prerequisite failure was reported as a passing skip:" >&2
    grep -Ein '^HARNESS_SKIP .*reason="[^"]*(failed|failure|could not)' "$log" >&2 || true
    exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' 0 HUP INT TERM
identities=$tmp_dir/identities
sed -n 's/^HARNESS_SKIP suite=\([^[:space:]]*\) test=\([^[:space:]]*\) .*/\1 \2/p' "$log" \
    | LC_ALL=C sort > "$identities"
duplicates=$tmp_dir/duplicates
uniq -d "$identities" > "$duplicates"
if [ -s "$duplicates" ]; then
    echo "check_skips: duplicate skip identity record(s):" >&2
    awk '{printf "  suite=%s test=%s\n", $1, $2}' "$duplicates" >&2
    exit 1
fi

if ! grep -Fq 'test result: ok.' "$log"; then
    echo "check_skips: log has no successful Cargo test result" >&2
    exit 1
fi

status=0
reject_native_skip() {
    pattern=$1
    if grep -Ei "^HARNESS_SKIP .*reason=\"[^\"]*${pattern}" "$log" >/dev/null; then
        echo "check_skips: $profile emitted a native-platform prerequisite skip matching '$pattern':" >&2
        grep -Ein "^HARNESS_SKIP .*reason=\"[^\"]*${pattern}" "$log" >&2 || true
        status=1
    fi
}

case "$profile" in
macos)
    reject_native_skip 'xcrun.*unavailable'
    reject_native_skip 'codesign.*unavailable'
    reject_native_skip 'clang.*unavailable'
    reject_native_skip 'SDK (path|version).*unavailable'
    reject_native_skip 'no macOS SDK (path|version)'
    reject_native_skip 'no libSystem\.tbd'
    reject_native_skip 'no Metal\.tbd'
    reject_native_skip 'no libc\+\+\.tbd'
    ;;
linux)
    reject_native_skip 'no GNU assembler'
    reject_native_skip 'no ar on this host'
    reject_native_skip 'no system ld'
    reject_native_skip 'no standard dynamic loader'
    ;;
esac

if [ "$status" -eq 0 ]; then
    echo "check_skips: $profile coverage clean ($records structured prerequisite skips)"
fi
exit "$status"
