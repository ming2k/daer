#!/usr/bin/env bash
# Install locally built daer binaries, datapath object, and systemd unit, plus a
# deployment configuration, then restart the service.
#
#   sudo scripts/ops/daer-install-netns.sh --config target/daer-global.toml
#
# The configuration is site-specific and may contain node credentials. It is
# passed explicitly and is never read from the repository: keep it under the
# ignored `target/` directory or outside the tree.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config=""

usage() {
    cat <<'EOF'
usage: sudo scripts/ops/daer-install-netns.sh --config <daer.toml>

Installs target/release/daer, target/release/daer-drb, target/ebpf/datapath.o and
install/daer.service, installs <daer.toml> as /etc/daer/config.toml, validates the
installed object, and restarts daer.

The config file is site-specific and may contain credentials; keep it out of git.
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
    echo "run this with sudo: sudo $0 --config <path>" >&2
    exit 2
fi

for file in \
    "$root/target/release/daer" \
    "$root/target/release/daer-drb" \
    "$root/target/ebpf/datapath.o" \
    "$root/install/daer.service"; do
    [[ -f "$file" ]] || { echo "missing $file; build it first" >&2; exit 1; }
done

install -Dm0755 "$root/target/release/daer" /usr/bin/daer
install -Dm0755 "$root/target/release/daer-drb" /usr/bin/daer-drb
install -Dm0644 "$root/target/ebpf/datapath.o" /usr/lib/daer/datapath.o
install -Dm0644 "$root/install/daer.service" /usr/lib/systemd/system/daer.service

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
/usr/bin/daer check -c /etc/daer/config.toml --object /usr/lib/daer/datapath.o

systemctl reset-failed daer >/dev/null 2>&1 || true
systemctl restart daer
sleep 2

echo "=== service status ==="
systemctl --no-pager --full status daer || true
echo
echo "=== topology ==="
ip netns list
ip -n daer0ns -o link show daer0peer 2>&1 || true
ip -n daer0ns -4 rule show 2>&1 || true
ip -n daer0ns route show 2>&1 || true
ip -n daer0ns -6 rule show 2>&1 || true
echo
echo "=== recent daemon log ==="
journalctl -u daer -n 60 --no-pager
