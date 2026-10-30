#!/usr/bin/env bash
# Fails when a pinned path dependency's checkout no longer matches pins/*.toml.
#
# The workspace depends on ../netune by path so both projects can move together.
# That convenience is only safe if the exact revision is recorded and reviewed:
# a netune change to TLS, DNS, socket options or health-check semantics silently
# changes daer's wire behaviour.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$root/pins/netune.toml"
status=0

rev() { sed -n 's/^rev[[:space:]]*=[[:space:]]*"\(.*\)"$/\1/p' "$pin_file"; }
path() { sed -n 's/^path[[:space:]]*=[[:space:]]*"\(.*\)"$/\1/p' "$pin_file"; }

pinned="$(rev)"
dep="$(cd "$root" && cd "$(path)" 2>/dev/null && pwd || true)"

if [ -z "$dep" ]; then
    echo "pins: netune checkout not found at $(path); run scripts/fetch-netune.sh" >&2
    exit 1
fi
if ! git -C "$dep" rev-parse --git-dir >/dev/null 2>&1; then
    echo "pins: $dep is not a git checkout; cannot verify the pin" >&2
    exit 1
fi

actual="$(git -C "$dep" rev-parse HEAD)"
if [ "$actual" != "$pinned" ]; then
    echo "pins: netune moved" >&2
    echo "  pinned: $pinned" >&2
    echo "  actual: $actual ($(git -C "$dep" describe --tags --always)/$(git -C "$dep" rev-parse --abbrev-ref HEAD))" >&2
    echo >&2
    echo "Review the diff, then update $pin_file:" >&2
    git -C "$dep" --no-pager log --oneline "$pinned..$actual" | sed 's/^/  /' >&2
    status=1
else
    echo "pins: netune ok ($pinned, $(git -C "$dep" describe --tags --always))"
fi

exit "$status"
