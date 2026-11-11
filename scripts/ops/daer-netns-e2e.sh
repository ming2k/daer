#!/usr/bin/env bash
# One-shot privileged check for a daer build with the private ingress namespace.
#
#   sudo scripts/ops/daer-netns-e2e.sh --config target/netns-e2e.toml
#
# The script owns daer0ns/daer0 and temporarily stops daer. It snapshots the host
# network state it can change and restores the original service state on every exit
# path, including Ctrl-C and failures. The config describes the node under test; it
# is site-specific, may contain credentials, and is never read from the repository.
#
# Environment:
#   DAER_E2E_WAN          WAN interface to watch (default: the default route's device)
#   DAER_E2E_LOG          daemon log path (default: target/daer-netns-e2e.log)
#   DAER_E2E_RESTORE_DIR  host-state snapshot directory (default: target/daer-netns-restore)
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config=""

usage() {
    cat <<'EOF'
usage: sudo scripts/ops/daer-netns-e2e.sh --config <daer.toml>

Runs the private-ingress end-to-end diagnostic against a locally built daemon.
The config file is required and may contain node credentials; keep it out of git.
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

log="${DAER_E2E_LOG:-$root/target/daer-netns-e2e.log}"
restore_dir="${DAER_E2E_RESTORE_DIR:-$root/target/daer-netns-restore}"
owner="${SUDO_USER:-root}"
wan_if="${DAER_E2E_WAN:-$(ip route show default 2>/dev/null | awk '/^default/{print $5; exit}')}"
[[ -n "$wan_if" ]] || wan_if=wlan0
daer_pid=""
daer_initial=""
resolved_initial=""
cleaned=0

# Remove daer's TC hooks from the WAN device. If a SIGKILL leaves them behind, they
# keep redirecting host traffic into a listener that no longer exists, which looks
# exactly like "the network died after running the test".
remove_daer_tc() {
    local direction pref
    for direction in ingress egress; do
        while read -r pref; do
            [[ -n "$pref" ]] || continue
            tc filter del dev "$wan_if" "$direction" pref "$pref" >/dev/null 2>&1
        done < <(tc filter show dev "$wan_if" "$direction" 2>/dev/null \
            | awk '/tproxy_/ { for (i = 1; i <= NF; i++) if ($i == "pref") print $(i + 1) }')
    done
}

cleanup() {
    set +e
    [[ "$cleaned" -eq 1 ]] && return
    cleaned=1

    # Stop the test daemon first, then remove the topology it may still own.
    if [[ -n "$daer_pid" ]] && kill -0 "$daer_pid" 2>/dev/null; then
        kill -TERM "$daer_pid" 2>/dev/null
        for _ in $(seq 1 150); do
            kill -0 "$daer_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$daer_pid" 2>/dev/null
        wait "$daer_pid" 2>/dev/null
    fi
    ip netns del daer0ns >/dev/null 2>&1
    ip link del daer0 >/dev/null 2>&1
    remove_daer_tc

    # Remove only daer's table/rule, never the operator's xray/vpn rules.
    for fam in -4 -6; do
        ip "$fam" rule del fwmark 0x8000000/0x8000000 table 2023 >/dev/null 2>&1
        ip "$fam" rule del iif daer0peer table 2023 >/dev/null 2>&1
        ip "$fam" route del local default dev lo table 2023 >/dev/null 2>&1
    done

    # Restore the host sysctls the datapath changes. The daemon normally restores
    # them on clean drop; this is the backstop for SIGKILL or a blocked shutdown.
    if [[ -f "$restore_dir/sysctls" ]]; then
        while IFS=$'\t' read -r key value; do
            [[ -n "$key" && -n "$value" ]] || continue
            printf '%s' "$value" >"/proc/sys/net/$key" 2>/dev/null
        done <"$restore_dir/sysctls"
    fi

    # Return the network to the service that owned it before this script.
    if [[ "$daer_initial" == "active" ]]; then
        systemctl reset-failed daer >/dev/null 2>&1
        systemctl start daer >/dev/null 2>&1 || echo "warning: could not restart daer" >&2
    fi

    # A daer run that captured the host resolver's UDP replies can leave
    # systemd-resolved in a backoff; restarting it is the clean way back.
    if [[ "$resolved_initial" == "active" ]] \
        && systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
        systemctl restart systemd-resolved >/dev/null 2>&1
    fi
    resolvectl flush-caches >/dev/null 2>&1
    chown -R "$owner" "$log"* "$restore_dir" "$root/target/daer-netns-e2e."*.txt 2>/dev/null
}

cd "$root" || exit 1
for file in target/release/daer target/ebpf/datapath.o; do
    [[ -f "$file" ]] || { echo "missing $file; build it first" >&2; exit 1; }
done

mkdir -p "$restore_dir" "$(dirname "$log")"
chown "$owner" "$restore_dir" 2>/dev/null
if systemctl is-active --quiet dae 2>/dev/null; then
    echo "dae is active; run scripts/ops/remove-dae.sh first" >&2
    exit 1
fi
daer_initial="$(systemctl is-active daer 2>/dev/null || true)"
resolved_initial="$(systemctl is-active systemd-resolved 2>/dev/null || true)"
echo "initial services: daer=$daer_initial systemd-resolved=$resolved_initial"
echo "wan interface:    $wan_if"

trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# Snapshot exactly what this script can change on the host.
{
    for key in \
        ipv4/ip_forward \
        ipv4/conf/all/forwarding \
        ipv4/conf/all/rp_filter \
        ipv4/conf/all/arp_filter \
        ipv6/conf/all/forwarding; do
        value="$(cat "/proc/sys/net/$key" 2>/dev/null || true)"
        [[ -n "$value" ]] && printf '%s\t%s\n' "$key" "$value"
    done
} >"$restore_dir/sysctls"
ip rule show >"$restore_dir/rules-before.txt" 2>&1
ip route show table 2023 >"$restore_dir/route-before.txt" 2>&1

# Stop the services that would otherwise own daer0/table 2023. Their state was
# captured above, and cleanup restarts exactly the ones that were active.
if [[ "$daer_initial" == "active" ]]; then systemctl stop daer >/dev/null 2>&1; fi
mkdir -p /run/netns
ip netns del daer0ns >/dev/null 2>&1
ip link del daer0 >/dev/null 2>&1
remove_daer_tc

# Find the node under test in the config, for the packet capture. The config is
# parsed loosely on purpose: a missing `server` only skips that capture.
node_target="$(sed -n 's/^[[:space:]]*server[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$config" | head -n 1)"
node_ip=""
if [[ -n "$node_target" ]]; then
    node_ip="$(timeout 5 getent ahostsv4 "$node_target" 2>/dev/null | awk 'NR == 1 { print $1 }')"
    [[ -n "$node_ip" ]] || node_ip="$node_target"
fi

: >"$log"
chown "$owner" "$log" 2>/dev/null

echo "=== baseline without daer (services restored after this run) ==="
curl -4 -sS --max-time 12 -o /dev/null -w 'direct-ip http=%{http_code}\n' http://1.1.1.1/ || true
curl -4 -sS --max-time 12 --resolve example.com:443:172.66.147.243 \
    -o /dev/null -w 'direct-example http=%{http_code}\n' https://example.com/ || true
timeout 8 getent ahostsv4 example.com | head -2 || true

echo "=== start daer ==="
RUST_LOG=daer=debug,daer_control=debug,daer_relay=debug,daer_outbound=debug,netune=debug \
    ./target/release/daer run -c "$config" --object target/ebpf/datapath.o >"$log" 2>&1 &
daer_pid=$!
chown "$owner" "$log" 2>/dev/null
echo "daer pid=$daer_pid log=$log"
for _ in $(seq 1 200); do
    grep -q "datapath attached" "$log" && break
    if ! kill -0 "$daer_pid" 2>/dev/null; then
        echo "daer exited during startup:" >&2
        tail -100 "$log" >&2
        exit 1
    fi
    sleep 0.1
done
if ! grep -q "datapath attached" "$log"; then
    echo "daer did not attach:" >&2
    tail -150 "$log" >&2
    exit 1
fi

echo
echo "=== topology ==="
ip netns list
ip -n daer0ns -o link show daer0peer
echo "-- ingress rules --"
ip -n daer0ns -4 rule show
ip -n daer0ns -4 route show table 2023
ip -n daer0ns -6 rule show
echo "-- host rules --"
ip rule show
echo "-- neighbor --"
ip -n daer0ns neigh show
echo "-- tc --"
tc filter show dev "$wan_if" egress | head -20
ip netns exec daer0ns tc filter show dev daer0peer ingress | head -20
echo "-- listener --"
ip netns exec daer0ns ss -lntup | grep 12345 || true

echo
echo "=== direct userspace path (literal IP, no DNS) ==="
curl -4 -sS --max-time 15 -o /dev/null -w 'http=%{http_code}\n' http://1.1.1.1/ || true
echo "-- sockets inside daer0ns --"
ip netns exec daer0ns ss -tanp | head -20
echo "-- sockets on host to 12345 --"
ss -tanp | grep -E ':12345' || true

echo
echo "-- raw UDP send from daer0ns with a non-local source --"
ip netns exec daer0ns python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
s.bind(("1.1.1.1", 53))
s.settimeout(2)
try:
    print("udp send bytes:", s.sendto(b"daer-probe", ("192.0.2.1", 45678)))
except Exception as error:
    print("udp send failed:", repr(error))
PY
echo
echo "=== DNS userspace path ==="
dns_capture="$root/target/daer-netns-e2e.dns.txt"
timeout 14 tcpdump -i "$wan_if" -nn -c 12 'udp port 53' >"$dns_capture" 2>&1 &
dns_pid=$!
sleep 1
timeout 15 getent ahostsv4 example.com | head -3 || true
sleep 1
kill "$dns_pid" 2>/dev/null || true
wait "$dns_pid" 2>/dev/null || true
chown "$owner" "$dns_capture" 2>/dev/null || true
echo "-- $wan_if DNS capture --"
cat "$dns_capture"
echo
echo "=== proxied path (pinned example.com) ==="
if [[ -n "$node_ip" ]]; then
    node_capture="$root/target/daer-netns-e2e.node.txt"
    timeout 30 tcpdump -i "$wan_if" -nn -c 20 "host $node_ip" >"$node_capture" 2>&1 &
    node_capture_pid=$!
    sleep 1
else
    echo "-- no node server found in $config; skipping the node capture --"
fi
proxy_status=$(curl -4 -sSL --max-time 30 --resolve example.com:443:172.66.147.243 \
    -o /dev/null -w '%{http_code}' https://example.com/ 2>"$log.curl" || true)
if [[ -n "$node_ip" ]]; then
    sleep 1
    kill "$node_capture_pid" 2>/dev/null || true
    wait "$node_capture_pid" 2>/dev/null || true
    chown "$owner" "$node_capture" 2>/dev/null || true
    echo "-- $wan_if capture for node --"
    cat "$node_capture"
fi
cat "$log.curl"
echo "example.com http=${proxy_status:-failed}"
echo
echo "=== relevant log ==="
grep -aE "flow decided|datagram|session|node selected|flow closed|accepted|rejected|failed|refused|no outbound|relay|dial" "$log" | tail -160 || true
echo
echo "=== bpf stats ==="
bpftool map dump name bpf_stats_map 2>&1 | tail -80 || true
echo
echo "=== nftables (for diagnosis) ==="
nft_capture="$root/target/daer-netns-e2e.nft.txt"
nft list ruleset >"$nft_capture" 2>&1 || true
chown "$owner" "$nft_capture" 2>/dev/null
wc -l "$nft_capture"

echo
echo "=== teardown ==="
# Explicit stop first so we can report a blocked shutdown, then the trap performs
# the same state restoration on any exit path.
kill -TERM "$daer_pid" 2>/dev/null || true
for _ in $(seq 1 150); do
    kill -0 "$daer_pid" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$daer_pid" 2>/dev/null; then
    echo "daemon did not stop on SIGTERM; last log:" >&2
    tail -80 "$log" >&2
    kill -KILL "$daer_pid" 2>/dev/null || true
fi
wait "$daer_pid" 2>/dev/null || true
daer_pid=""
for _ in $(seq 1 50); do
    ip netns list 2>/dev/null | grep -q daer0ns || break
    sleep 0.1
done
if ip netns list 2>/dev/null | grep -q daer0ns; then
    echo "namespace daer0ns still exists; cleanup will remove it" >&2
else
    echo "namespace removed"
fi
if ip link show daer0 >/dev/null 2>&1; then
    echo "daer0 still exists; cleanup will remove it" >&2
else
    echo "veth pair removed"
fi

echo
echo "=== restoring the pre-run network state ==="
cleanup
trap - EXIT INT TERM
echo "services now: daer=$(systemctl is-active daer 2>/dev/null || true)"
ip rule show
curl -4 -sS --max-time 8 -o /dev/null -w 'restored-ip http=%{http_code}\n' http://1.1.1.1/ || true
timeout 8 getent ahostsv4 example.com | head -2 || true

if [[ "$proxy_status" != "200" ]]; then
    echo "proxied request failed; full log: $log" >&2
    exit 1
fi
plain_log="$log.plain"
sed -E 's/\x1b\[[0-9;]*[mK]//g' "$log" >"$plain_log"
chown "$owner" "$plain_log" 2>/dev/null
if ! grep -q "outbound=proxy" "$plain_log"; then
    echo "example.com returned 200 but no proxy decision appears in $plain_log" >&2
    exit 1
fi
echo "proxied request returned 200 and the daemon selected the proxy outbound"
echo "log: $log"
