#!/usr/bin/env bash
# Stage locally built daer artifacts, install them with the systemd unit and a deployment
# configuration, and restart the service.
#
#   scripts/ops/daer-install-netns.sh --config target/daer-global.toml
#
# Run it as your normal user. The staging half invokes `cargo xtask install` in your
# environment; the script then re-execs itself under sudo to copy the staged tree, install
# the configuration, and restart the unit. The file list belongs to `cargo xtask install`,
# so this script cannot install a different set.
#
# The configuration is site-specific and may contain node credentials. It is passed
# explicitly and is never read from the repository: keep it under the ignored `target/`
# directory or outside the tree.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config=""
staged=""

usage() {
    cat <<'EOF'
usage: scripts/ops/daer-install-netns.sh --config <daer.toml>

Stages target/release/{daer,daer-drb}, target/ebpf/datapath.bpf.o and
install/daer.service with `cargo xtask install`, copies the staged tree into /usr,
installs <daer.toml> as /etc/daer/config.toml, validates the installed object, and
restarts daer.

Run it as your normal user; it re-execs itself under sudo. The config file is
site-specific and may contain credentials; keep it out of git.

Internal option used by the sudo re-exec:
  --staged <dir>   copy an already staged tree instead of building one
EOF
}

while (($# > 0)); do
    case "$1" in
        --config)
            [[ $# -ge 2 ]] || { echo "error: --config needs a path" >&2; exit 2; }
            config="$2"
            shift 2
            ;;
        --config=*)
            config="${1#*=}"
            shift
            ;;
        --staged)
            [[ $# -ge 2 ]] || { echo "error: --staged needs a path" >&2; exit 2; }
            staged="$2"
            shift 2
            ;;
        --staged=*)
            staged="${1#*=}"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ -n "$config" ]] || { echo "error: --config is required" >&2; usage >&2; exit 2; }
[[ -f "$config" ]] || { echo "error: config not found: $config" >&2; exit 1; }
config="$(cd "$(dirname "$config")" && pwd)/$(basename "$config")"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if [[ -z "$staged" ]]; then
        staged="$root/target/install-root"
        # A stale tree from a previous run would install files this run did not produce.
        # An explicit --staged tree belongs to the caller and is never deleted here.
        rm -rf "$staged"
    fi
    echo "=== staging with cargo xtask install ==="
    (cd "$root" && cargo xtask install --prefix /usr --destdir "$staged")
    staged="$(cd "$(dirname "$staged")" && pwd)/$(basename "$staged")"
    exec sudo -- "$script" --staged "$staged" --config "$config"
fi

if [[ -z "$staged" ]]; then
    echo "error: run this as your normal user (it re-execs with sudo), or pass --staged <dir>" >&2
    exit 2
fi
staged="$(cd "$(dirname "$staged")" && pwd)/$(basename "$staged")"
[[ -d "$staged/usr" ]] || { echo "error: staged tree not found: $staged/usr" >&2; exit 1; }

# Copy the staged tree as a tree, not as a list of filenames. Modes are preserved; ownership
# is not, so root owns the installed files regardless of who staged them. `-f` replaces a
# destination that cannot be opened for writing, which is what a running binary would
# otherwise report as "Text file busy".
cp -Rf --preserve=mode,timestamps "$staged/usr/." /usr/

# Files removed from the install set are removed from the host too. `daer-cleanup` was
# deleted in ADR-0042; leaving it installed would make an old unit hook or operator command
# look supported. `datapath.o` is the pre-rename object path.
rm -f /usr/bin/daer-cleanup /usr/lib/daer/datapath.o
# Artifacts written by an older build may predate the explicit 0600/0700 modes.
# Only tighten daemon-owned state; do not recursively chmod operator rule sets.
chmod -R go-rwx /run/daer /var/lib/daer/incidents /etc/daer/persist.d 2>/dev/null || true

staged_config="$(mktemp)"
trap 'rm -f "$staged_config"' EXIT
cp "$config" "$staged_config"

if [[ -f /etc/daer/config.toml ]]; then
    stamp="$(date +%Y%m%d-%H%M%S)"
    cp -a /etc/daer/config.toml "/etc/daer/config.toml.bak-$stamp"
    echo "backed up /etc/daer/config.toml -> /etc/daer/config.toml.bak-$stamp"
fi
install -Dm0640 "$staged_config" /etc/daer/config.toml

systemctl daemon-reload
echo "=== daer check (installed object) ==="
/usr/bin/daer check -c /etc/daer/config.toml --object /usr/lib/daer/datapath.bpf.o --host

systemctl reset-failed daer >/dev/null 2>&1 || true
systemctl restart daer
sleep 2

echo "=== service status ==="
systemctl --no-pager --full status daer || true
echo
echo "=== topology ==="
daer_pid="$(systemctl show -p MainPID --value daer 2>/dev/null || true)"
if [[ -n "$daer_pid" && "$daer_pid" != "0" ]]; then
    # The namespace mount is private to the daemon's mount namespace. Enter that mount
    # namespace with nsenter; a path through /proc/<pid>/root does not cross the private
    # bind mount, so it would show the empty underlying /run/netns instead.
    ns_mnt="/proc/$daer_pid/ns/mnt"
    if command -v nsenter >/dev/null 2>&1; then
        nsenter --mount="$ns_mnt" ip netns list 2>&1 || true
        nsenter --mount="$ns_mnt" ip -n daer0ns -o link show daer0peer 2>&1 || true
        nsenter --mount="$ns_mnt" ip -n daer0ns -4 rule show 2>&1 || true
        nsenter --mount="$ns_mnt" ip -n daer0ns route show 2>&1 || true
        nsenter --mount="$ns_mnt" ip -n daer0ns -6 rule show 2>&1 || true
    else
        echo "nsenter (util-linux) is not installed; skipping the ingress topology" >&2
    fi
else
    echo "daer is not running; no ingress namespace to inspect" >&2
fi
echo
echo "=== recent daemon log ==="
journalctl -u daer -n 60 --no-pager
