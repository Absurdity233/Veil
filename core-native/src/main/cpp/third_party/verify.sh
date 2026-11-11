#!/bin/sh
# Verifies the vendored Monocypher sources have not changed.
#
# A cryptographic primitive that silently differs from the one that was
# reviewed is worse than no vendoring at all, and this is the only third-party
# code compiled into the client. Run in CI, and after any upgrade.
#
#   ./verify.sh            check against the recorded hashes
#   ./verify.sh --update   record the current hashes (after a deliberate bump)

set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
MONO="$DIR/monocypher"
RECORD="$DIR/.monocypher.sha256"

FILES="monocypher.c monocypher.h monocypher-ed25519.c monocypher-ed25519.h LICENCE.md"

hash_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        echo "verify: neither sha256sum nor shasum is available" >&2
        exit 2
    fi
}

compute() {
    for f in $FILES; do
        printf '%s  %s\n' "$(hash_of "$MONO/$f")" "$f"
    done
}

if [ "${1:-}" = "--update" ]; then
    compute > "$RECORD"
    echo "verify: recorded $(printf '%s' "$FILES" | wc -w) hashes in $RECORD"
    exit 0
fi

if [ ! -f "$RECORD" ]; then
    echo "verify: no recorded hashes; run with --update once and commit the result" >&2
    exit 1
fi

current="$(compute)"
if [ "$current" = "$(cat "$RECORD")" ]; then
    echo "verify: vendored Monocypher matches the recorded hashes"
    exit 0
fi

echo "verify: vendored Monocypher has changed" >&2
printf '%s\n' "$current" >&2
echo "--- expected ---" >&2
cat "$RECORD" >&2
exit 1