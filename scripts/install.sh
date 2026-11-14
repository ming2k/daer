#!/usr/bin/env bash
# Build daer and install it under /usr.
#
#   scripts/install.sh
#
# Run it as your normal user. The builds run as you; `sudo` is used only for the
# installation step and the systemd unit reload.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "error: run this as your normal user; it uses sudo for the install step" >&2
    exit 2
fi

echo "==> building release binaries"
cargo build --release -p daer-cli -p daer-drb --bins

echo "==> building the kernel datapath object"
cargo xtask ebpf

echo "==> staging the install tree"
# Stage as you, never as root: the staging binary is a build artifact, and a compromised
# `target/` must not execute as root. `cargo xtask install` still owns the file list.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
target/debug/xtask install --prefix /usr --destdir "$stage"

echo "==> installing to /usr"
# Install file by file. A recursive `cp --preserve=mode` of `stage/usr/.` to `/usr/`
# would also apply the staged directory modes to `/usr`, `/usr/bin` and `/usr/lib`;
# with a restrictive umask that can chmod `/usr` to 0700. `install -D` copies only
# the files and creates missing parents. It also replaces a running executable.
while IFS= read -r -d '' src; do
    rel="${src#"$stage/"}"
    mode="$(stat -c '%a' "$src")"
    sudo install -Dm"$mode" "$src" "/$rel"
done < <(find "$stage" -type f -print0)

# Legacy paths are not in the current install set; xtask removes them from a reused
# staging tree, and the live tree needs the same cleanup.
sudo rm -f /usr/bin/daer-cleanup /usr/lib/daer/datapath.o

sudo systemctl daemon-reload
echo "installed; restart with: sudo systemctl restart daer"
