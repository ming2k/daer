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

section "2. building the test binaries (as $builder, so cargo is findable)"
build_one() {
    local pkg="$1" target="$2" var="$3" log="$logs/build-$2.log"
    if ! as_builder env -u SUDO_USER cargo test -p "$pkg" --test "$target" --no-run \
            >"$log" 2>&1; then
        bad "the $target test binary did not build; see $log"
        sed -n '$p' "$log" | sed 's/^/       /'
        printf -v "$var" '%s' ""
        return
    fi
    local bin
    bin="$(ls -t "target/debug/deps/$target"-* 2>/dev/null | grep -v '\.d$' | head -n 1)"
    if [[ -z "$bin" ]]; then
        bad "no $target test binary under target/debug/deps"
        printf -v "$var" '%s' ""
    else
        ok "binary: $bin"
        printf -v "$var" '%s' "$bin"
    fi
}

binary_transparent=""
binary_netns=""
binary_reload=""
build_one daer-control transparent binary_transparent
build_one daer-control netns_lifecycle binary_netns
build_one daer-cli reload binary_reload

section "3. the transparent data path (a real tproxy redirect into a real origin)"
# `tests/transparent.rs` is the only proof that a redirected flow is actually proxied, and it
# installs its own `nftables tproxy` rule. The test creates and removes its own
# `ip daer-test` table, so this script does not disturb the operator's rules.
if ! command -v nft >/dev/null 2>&1; then
    skip "3-tcp" "nft is not installed; the transparent-path test cannot install its redirect"
elif [[ -z "$binary_transparent" ]]; then
    skip "3-tcp" "no transparent test binary; the build failed above"
else
    if "$binary_transparent" --nocapture --test-threads=1 >"$logs/transparent.log" 2>&1 \
            && grep -q "test result: ok" "$logs/transparent.log"; then
        # Report each path separately: the datagram test skips itself on a box that cannot
        # create a second network namespace while the TCP path — the one that matters — passes.
        if grep -q "a_redirected_flow_is_proxied_by_the_daemon ... ok" "$logs/transparent.log"; then
            ok "a redirected flow reached the daemon, was proxied, and the origin's nonce came back"
        else
            bad "the TCP data path did not report a pass; see $logs/transparent.log"
        fi
        if grep -q "a_redirected_datagram_is_proxied_by_the_daemon ... ok" "$logs/transparent.log"; then
            ok "a redirected datagram reached the daemon and the reply came back to the client port"
        else
            skip "3-udp" "the UDP path skipped itself (a second network namespace is needed); see $logs/transparent.log"
        fi
        grep -E "^test " "$logs/transparent.log" | sed 's/^/       /'
    else
        bad "the transparent data path failed; see $logs/transparent.log"
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/transparent.log" 2>/dev/null \
            | awk '/panicked|assertion|must/{print "       " $0; if (++n == 3) exit}'
    fi
fi

section "3a. the private ingress namespace"
# This owns daer0ns and daer0/daer0peer for the duration of one test. It proves the namespace
# is created, the peer moves, the policy is ingress-keyed, the return route exists, and drop
# removes both the namespace and the host end. A running daer service must be stopped first.
if [[ -z "$binary_netns" ]]; then
    skip "3-netns" "no netns_lifecycle test binary; the build failed above"
elif systemctl is-active --quiet daer 2>/dev/null; then
    skip "3-netns" "the daer service is running and owns daer0ns; stop it before this check"
else
    if DAER_NETNS_TEST=1 "$binary_netns" --nocapture --test-threads=1 \
            >"$logs/netns.log" 2>&1 && grep -q "test result: ok" "$logs/netns.log"; then
        ok "daer0ns, the peer move, iif policy, return route, and teardown all hold"
        grep -E "^test " "$logs/netns.log" | sed 's/^/       /'
    else
        bad "the private ingress lifecycle failed; see $logs/netns.log"
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$logs/netns.log" 2>/dev/null \
            | awk '/panicked|assertion|must/{print "       " $0; if (++n == 3) exit}'
    fi
fi

section "4. reload: a SIGHUP must not abort the daemon"
# `daer run` used to panic on its first `SIGHUP` because `reload` called `block_on` inside the
# multi-threaded runtime. No unit test could catch it: the defect is in the interaction between
# the signal loop and the runtime, so it needs a real process and a real signal.
if [[ -z "$binary_reload" ]]; then
    skip "4" "no reload test binary; the build failed above"
elif [[ ! -x "$binary_reload" ]]; then
    bad "reload test binary is not executable: $binary_reload"
else
    if "$binary_reload" --nocapture --test-threads=1 >"$logs/reload.log" 2>&1 \
            && grep -q "test result: ok" "$logs/reload.log"; then
        if grep -q "skipped: the daemon could not start here" "$logs/reload.log"; then
            skip "4" "the reload test skipped itself; see $logs/reload.log"
        else
            ok "the daemon survived SIGHUP and published generation 2"
        fi
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
