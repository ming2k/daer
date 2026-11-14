#!/usr/bin/env bash
# Verifies the user-space data path end to end, on a machine that has CAP_NET_ADMIN.
#
#     ./scripts/verify/e2e-check.sh          # will re-exec itself with sudo
#     sudo ./scripts/verify/e2e-check.sh     # or run it directly
#
# # Why this is not part of kernel-check.sh
#
# `kernel-check.sh` answers one question: **does the eBPF object load and behave** — verifier
# acceptance, tc attachment, the device pair, and the in-kernel datapath cases. Everything it
# checks depends only on `daer-ebpf` and `clang`.
#
# This script answers a different one: **does a real redirected flow reach the daemon and come
# back**. That depends on `daer-control`, the relay, nftables and a live `daer run` process —
# a large part of the workspace that has nothing to do with the datapath.
#
# Keeping them in one script was a defect, not a convenience: a compilation error anywhere in
# the user-space dependency graph turned the whole run red and made a passing verifier look
# broken. The two questions have different blast radii, different dependencies, and different
# reasons to fail, so they are separate gates.
#
# # The privilege boundary
#
# `cargo` lives in the invoking user's home and sudo resets PATH, so the test binaries are
# built as the invoking user and only the binaries themselves run under sudo.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

if [[ -t 1 ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BOLD=''; OFF=''
fi

failures=0
skips=0

say()   { printf '%s%s%s\n' "$1" "$2" "$OFF"; }
ok()    { printf '%s  ok  %s %s\n' "$GREEN" "$OFF" "$1"; }
bad()   { printf '%s fail %s %s\n' "$RED" "$OFF" "$1"; failures=$((failures + 1)); }
section() { printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }

# A skip states its reason; `DAER_REQUIRE` names the keys that must not skip.
skip() {
    local key="$1" message="$2"
    if [[ -n "$key" && ",${DAER_REQUIRE:-}," == *",$key,"* ]]; then
        printf '%s fail %s %s (check %s is in DAER_REQUIRE=%s, so a skip is a failure)\n' \
            "$RED" "$OFF" "$message" "$key" "$DAER_REQUIRE"
        failures=$((failures + 1))
        return
    fi
    printf '%s skip %s %s\n' "$YELLOW" "$OFF" "$message"
    skips=$((skips + 1))
}

builder="${SUDO_USER:-$(id -un)}"
logs="${SUDO_USER:+$(eval echo "~$SUDO_USER")/daer-e2e-check}"
logs="${logs:-$PWD/target/e2e-check}"
logs="${DAER_E2E_LOGS:-$logs}"
mkdir -p "$logs" 2>/dev/null || logs="$PWD/target/e2e-check"
mkdir -p "$logs"
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$builder" "$logs" 2>/dev/null || true
fi

as_builder() { if [[ -n "${SUDO_USER:-}" ]]; then runuser -u "$builder" -- "$@"; else "$@"; fi; }

section "0. invocation"
say "$BOLD" "building as: $builder"
say "$BOLD" "logs:        $logs"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    say "$YELLOW" "re-executing with sudo (the tests need CAP_NET_ADMIN and a real daemon)"
    exec sudo --preserve-env=DAER_REQUIRE,DAER_E2E_LOGS "$0" "$@"
fi

section "1. environment"
for tool in nft ip; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool present"
    else
        bad "$tool is missing; the transparent-path test cannot install its redirect"
    fi
done
ok "kernel $(uname -r)"
# The transparent tests use the loopback origin. In a disposable `unshare -n` namespace
# `lo` starts down, so bring it up here; on a normal host this is already true and the
# command is idempotent.
if ip link set lo up 2>/dev/null; then
    ok "loopback is up"
else
    bad "cannot bring loopback up"
fi

section "2. building the workspace E2E test binary (as $builder, so cargo is findable)"
# One test target contains every privileged case. The old script built six separate binaries,
# which linked the same dependency graph six times; `tests/e2e/main.rs` is one link and one
# discovery step. The individual test functions are selected by name below.
# The reload test starts the real binary, so both artifacts are built as the invoking user.
if ! as_builder env -u SUDO_USER cargo build -p daer-cli --bin daer \
        >"$logs/build-daemon.log" 2>&1; then
    bad "the daemon binary did not build; see $logs/build-daemon.log"
fi

binary_e2e=""
if ! as_builder env -u SUDO_USER cargo test -p daer-tests --test e2e --no-run \
        >"$logs/build-e2e.log" 2>&1; then
    bad "the workspace e2e test binary did not build; see $logs/build-e2e.log"
    sed -n '$p' "$logs/build-e2e.log" | sed 's/^/       /'
else
    binary_e2e="$(find target/debug -type f -name 'e2e-*' -perm -u+x \
        -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-)"
    if [[ -z "$binary_e2e" ]]; then
        bad "no e2e test binary under target/debug"
    else
        ok "binary: $binary_e2e"
    fi
fi

# Runs one test by exact name, with root privileges. `sudo` wrapped the script as a whole;
# this function only makes the selection explicit.
run_exact() {
    local log="$1" name="$2"
    shift 2
    if [[ -z "$binary_e2e" ]]; then
        return 125
    fi
    "$binary_e2e" --exact --nocapture --test-threads=1 "$name" "$@" >"$log" 2>&1
}

# True when exactly the selected test ran, even if it skipped itself.
exact_finished() {
    grep -q "test result: ok. 1 passed" "$1"
}

# True only when the selected test ran and did not print a skip reason.
exact_passed() {
    exact_finished "$1" && ! exact_skipped "$1"
}

exact_skipped() {
    grep -q "skipped: " "$1"
}

section "3. the transparent data path (a real tproxy redirect into a real origin)"
# `control_transparent.rs` installs its own `nftables tproxy` rule and removes its own
# `ip daer-test` table. The TCP positive control is paired with a negative control that must
# fail without the daemon; the datagram relay wiring is the in-process half of UDP.
if ! command -v nft >/dev/null 2>&1; then
    skip "3-tcp" "nft is not installed; the transparent-path test cannot install its redirect"
elif [[ -z "$binary_e2e" ]]; then
    skip "3-tcp" "no e2e test binary; the build failed above"
else
    run_exact "$logs/transparent-tcp.log" control_transparent::a_redirected_flow_is_proxied_by_the_daemon
    if exact_skipped "$logs/transparent-tcp.log"; then
        skip "3-tcp" "the TCP data path skipped itself (no CAP_NET_ADMIN or nftables); see $logs/transparent-tcp.log"
    else
        tcp_ok=0
        exact_passed "$logs/transparent-tcp.log" && tcp_ok=1
        run_exact "$logs/transparent-negative.log" control_transparent::the_negative_control_fails_without_the_daemon
        if [[ "$tcp_ok" -eq 1 ]] && exact_passed "$logs/transparent-negative.log"; then
            ok "a redirected flow reached the daemon and the negative control failed without it"
        else
            bad "the TCP data path or its negative control failed; see $logs/transparent-tcp.log and $logs/transparent-negative.log"
            perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/transparent-tcp.log" 2>/dev/null \
                | awk '/panicked|assertion|must/{print "       " $0; if (++n == 3) exit}'
        fi
    fi

    run_exact "$logs/transparent-tcp6.log" control_transparent::a_redirected_ipv6_flow_is_proxied_by_the_daemon
    if exact_passed "$logs/transparent-tcp6.log"; then
        ok "the IPv6 TCP path reached the daemon and returned the origin's nonce"
    elif exact_skipped "$logs/transparent-tcp6.log"; then
        skip "3-tcp6" "the IPv6 TCP path skipped itself (no usable IPv6 loopback); see $logs/transparent-tcp6.log"
    else
        bad "the IPv6 TCP data path failed; see $logs/transparent-tcp6.log"
    fi

    run_exact "$logs/transparent-wiring.log" control_transparent::the_datagram_relay_is_wired_into_the_daemon
    if exact_passed "$logs/transparent-wiring.log"; then
        ok "the datagram relay is wired into the daemon"
    else
        bad "the datagram relay wiring failed; see $logs/transparent-wiring.log"
    fi

    # The single-namespace IPv4 UDP fixture is invalid: the origin and the transparent reply
    # socket must own the same address and port. The two-namespace tests own that path.
    skip "3-udp" "the single-namespace IPv4 UDP fixture is invalid; 3-udp4 is the real gate"
fi

section "3a. IPv6 UDP through a real two-namespace tproxy topology"
# The test creates a client namespace, an origin namespace and the veth/nft/policy fixture
# itself. A skip means the host cannot create namespaces; `DAER_REQUIRE=3-udp4,3-udp6` makes
# that a failure in the privileged CI job.
if [[ -z "$binary_e2e" ]]; then
    skip "3-udp6" "no e2e test binary; the build failed above"
else
    run_exact "$logs/transparent-udp6.log" control_transparent_udp6::a_redirected_ipv6_datagram_is_proxied_by_the_daemon
    if exact_passed "$logs/transparent-udp6.log"; then
        ok "a redirected IPv6 datagram reached the daemon and the reply returned"
    elif exact_skipped "$logs/transparent-udp6.log"; then
        skip "3-udp6" "the IPv6 UDP topology skipped itself; see $logs/transparent-udp6.log"
    else
        bad "the IPv6 UDP data path failed; see $logs/transparent-udp6.log"
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/transparent-udp6.log" 2>/dev/null \
            | awk '/panicked|assertion|must/{print "       " $0; if (++n == 3) exit}'
    fi
fi

section "3b. IPv4 UDP through a real two-namespace tproxy topology"
# The IPv4 variant owns the same client/origin topology as the IPv6 test. It is the gate that
# closes the long-standing "IPv4 UDP not proven" gap; `3-udp4` makes its skip fatal in CI.
if [[ -z "$binary_e2e" ]]; then
    skip "3-udp4" "no e2e test binary; the build failed above"
else
    run_exact "$logs/transparent-udp4.log" control_transparent_udp4::a_redirected_ipv4_datagram_is_proxied_by_the_daemon
    if exact_passed "$logs/transparent-udp4.log"; then
        ok "a redirected IPv4 datagram reached the daemon and the reply returned"
    elif exact_skipped "$logs/transparent-udp4.log"; then
        skip "3-udp4" "the IPv4 UDP topology skipped itself; see $logs/transparent-udp4.log"
    else
        bad "the IPv4 UDP data path failed; see $logs/transparent-udp4.log"
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/transparent-udp4.log" 2>/dev/null \
            | awk '/panicked|assertion|must/{print "       " $0; if (++n == 3) exit}'
    fi
fi

section "3c. the private ingress namespace"
# This owns daer0ns and daer0/daer0peer for the duration of one test. It proves the namespace
# is created, the peer moves, the policy is ingress-keyed, the return route exists, and drop
# removes both the namespace and the host end. A running daer service must be stopped first.
if [[ -z "$binary_e2e" ]]; then
    skip "3-netns" "no e2e test binary; the build failed above"
elif systemctl is-active --quiet daer 2>/dev/null; then
    skip "3-netns" "the daer service is running and owns daer0ns; stop it before this check"
else
    DAER_NETNS_TEST=1 run_exact "$logs/netns-prepare.log" control_netns_lifecycle::prepare_and_drop_the_private_ingress
    DAER_NETNS_TEST=1 run_exact "$logs/netns-listener.log" control_netns_lifecycle::the_transparent_listener_binds_inside_the_namespace
    if exact_skipped "$logs/netns-prepare.log" || exact_skipped "$logs/netns-listener.log"; then
        skip "3-netns" "the private ingress test skipped itself; see $logs/netns-prepare.log and $logs/netns-listener.log"
    elif exact_passed "$logs/netns-prepare.log" && exact_passed "$logs/netns-listener.log"; then
        ok "daer0ns, the peer move, iif policy, return route, and teardown all hold"
    else
        bad "the private ingress lifecycle failed; see $logs/netns-prepare.log and $logs/netns-listener.log"
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/netns-prepare.log" "$logs/netns-listener.log" 2>/dev/null \
            | awk '/panicked|assertion|must/{print "       " $0; if (++n == 3) exit}'
    fi
fi

# TCX delivery is not gated here: the transparent tests above drive the userspace relay
# through an nftables redirect, not the eBPF TC hooks. The real-daemon script
# `scripts/ops/daer-delivery-check.sh` is the TCX delivery and SIGKILL-lifetime gate, and the
# privileged kernel suite has the TCX attach test.

section "4. reload: a SIGHUP must not abort the daemon"
# `daer run` used to panic on its first `SIGHUP` because `reload` called `block_on` inside the
# multi-threaded runtime. No unit test could catch it: the defect is in the interaction between
# the signal loop and the runtime, so it needs a real process and a real signal.
if [[ -z "$binary_e2e" ]]; then
    skip "4" "no e2e test binary; the build failed above"
else
    run_exact "$logs/reload.log" cli_reload::the_daemon_survives_a_hangup_and_publishes_a_new_generation
    if exact_passed "$logs/reload.log"; then
        ok "the daemon survived SIGHUP and published generation 2"
    elif exact_skipped "$logs/reload.log"; then
        skip "4" "the reload test skipped itself; see $logs/reload.log"
    else
        bad "reload failed; see $logs/reload.log"
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/reload.log" 2>/dev/null \
            | awk '/panicked|Cannot start a runtime|did not publish|must not abort/\
                   {print "       " $0; if (++n == 3) exit}'
    fi
fi

section "summary"
if [[ "$failures" -eq 0 ]]; then
    printf '%s%sAll user-space checks passed.%s\n' "$GREEN" "$BOLD" "$OFF"
    # A skip is reported on the green path too: otherwise a run that proved nothing prints
    # the same line as one that proved everything (ADR-0007).
    if [[ "$skips" -gt 0 ]]; then
        printf '%s%d check(s) skipped — read the reasons above before treating this as full coverage.%s\n' \
            "$YELLOW" "$skips" "$OFF"
        printf 'Set DAER_REQUIRE=<key,...> (e.g. 3-tcp,4) to make a skip fatal in CI.\n'
    else
        printf 'No check was skipped: every gate above ran and passed.\n'
    fi
    printf 'Logs: %s\n' "$logs"
    printf 'The kernel side is a different question: %ssudo ./scripts/verify/kernel-check.sh%s\n' \
        "$BOLD" "$OFF"
    exit 0
fi
printf '%s%s%d check(s) failed, %d skipped.%s\n' "$RED" "$BOLD" "$failures" "$skips" "$OFF"
printf 'Logs are in %s — send them along.\n' "$logs"
exit 1
