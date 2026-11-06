#!/usr/bin/env bash
# Verifies the kernel datapath on a machine that has CAP_BPF.
#
#     ./scripts/kernel-check.sh          # will re-exec itself with sudo
#     sudo ./scripts/kernel-check.sh     # or run it directly
#
# # The privilege boundary
#
# `cargo` and `rustup` usually live in the invoking user's home, so `sudo cargo` does not
# find them: sudo resets PATH to root's. This script therefore builds the test binaries as
# the invoking user and only puts `sudo` around the binaries themselves. Everything else —
# log files, temporary files — is written where the invoking user can write, never to a
# path that happens to exist but is owned by someone else.
#
# It never leaves kernel state behind: every interface it creates is removed at the end.
# Read the summary even if it exits non-zero — a `skip` is not a failure, a `fail` is.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 1

# ── terminal ────────────────────────────────────────────────────────────────
# Colour only when attached to a tty, so a redirected log is readable.
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
skip()  {
    # A skip is a fact on a developer's box and a hole in CI. `DAER_REQUIRE` names the checks that
    # must **not** skip here, as a comma-separated list of keys (`"7-tcp,8"`); a skip in one of
    # them is a failure, because a green run that proved nothing is the exact failure mode
    # ADR-0007 exists to prevent.
    #
    # Keys rather than section numbers: the UDP half of section 7 has a named prerequisite (a
    # second network namespace) that a container cannot satisfy, so promoting it to a failure
    # would make the whole gate unrunnable where it matters most. It stays a skip that states
    # its reason, and `docs/dev/roadmap.md` carries it as the open gap it is.
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

# Not named `head`: defining a function called `head` shadows the command for the rest of
# the script, so any later `head -3` calls the function instead. That is what silently broke
# the failure output the first time this ran.
section() { printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }

# ── who we are ──────────────────────────────────────────────────────────────
# `SUDO_USER` is set by sudo; otherwise we are the user. Building as this user is what keeps
# `cargo` findable.
builder="${SUDO_USER:-$(id -un)}"
# The directory the *invoking* user can write, for logs and the build.
logs="${DAER_LOG_DIR:-}"
if [[ -z "$logs" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        logs="$(eval echo "~$SUDO_USER")/daer-kernel-check"
    else
        logs="$PWD/target/kernel-check"
    fi
fi
mkdir -p "$logs" 2>/dev/null
if [[ -z "${SUDO_USER:-}" ]]; then
    chown -R "$builder" "$logs" 2>/dev/null || true
fi

# ── privilege ───────────────────────────────────────────────────────────────
if [[ "${1:-}" != "--as-root" && "$(id -u)" -ne 0 ]]; then
    printf '%sAttaching a tc program needs CAP_BPF and CAP_NET_ADMIN; re-running under sudo.%s\n' \
        "$BOLD" "$OFF"
    exec sudo --preserve-env=DAER_OBJECT,DAER_LOG_DIR "$0" --as-root
fi

section "0. invocation"
say "$BOLD" "building as: $builder"
say "$BOLD" "logs:        $logs"

# Runs a command as the invoking user, so `cargo` resolves.
as_builder() {
    if [[ -n "${SUDO_USER:-}" && "$(id -un)" == root ]]; then
        sudo -u "$builder" --preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME "$@"
    else
        "$@"
    fi
}

section "1. environment"

for command in ip tc bpftool clang; do
    command -v "$command" >/dev/null 2>&1 && ok "$command present" || bad "$command is missing"
done
ok "kernel $(uname -r)"
[[ -f /sys/kernel/btf/vmlinux ]] \
    && ok "BTF available (CO-RE will work)" \
    || bad "no /sys/kernel/btf/vmlinux: the object cannot relocate"

# The capability check is explicit rather than inferred from a failed load: a
# `PermissionDenied` from `bpf()` looks identical whether the cause is a missing capability
# or `unprivileged_bpf_disabled`.
if command -v capsh >/dev/null 2>&1; then
    if capsh --has-p=cap_bpf 2>/dev/null && capsh --has-p=cap_net_admin 2>/dev/null; then
        ok "CAP_BPF and CAP_NET_ADMIN are effective"
    else
        bad "CAP_BPF / CAP_NET_ADMIN are not effective; bpf() will refuse map creation"
    fi
fi
# This is a property of the machine, not a check that was skipped: with the sysctl set,
# unprivileged `bpf()` is refused, and that is the *correct* configuration for a box that
# runs the datapath as a service. Saying "skip" here counted it against the run and made a
# fully-proving green summary read as "3 skipped".
if [[ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 0)" != "0" ]]; then
    ok "unprivileged bpf() is disabled (expected; this script runs with real capabilities)"
fi

section "2. datapath object"
object="${DAER_OBJECT:-target/ebpf/datapath.o}"
if [[ ! -f "$object" ]]; then
    bad "$object missing; run 'cargo xtask ebpf' first"
    printf '\n%sCannot continue without the object.%s\n' "$RED" "$OFF"
    exit 1
fi
ok "$object ($(stat -c %s "$object") bytes)"

section "3. building the test binaries (as $builder, so cargo is findable)"
if ! as_builder env -u SUDO_USER cargo test -p daer-ebpf --test kernel --no-run \
        >"$logs/build.log" 2>&1; then
    bad "the kernel test binary did not build; see $logs/build.log"
    sed -n '$p' "$logs/build.log" | sed 's/^/       /'
fi
binary="$(ls -t target/debug/deps/kernel-* 2>/dev/null | grep -v '\.d$' | head -n 1)"
if [[ -z "$binary" ]]; then
    bad "no kernel test binary under target/debug/deps"
    binary=""
else
    ok "binary: $binary"
fi

# The in-kernel datapath cases (ADR-0022) live in their own test target. Building it here
# is what makes section 9 possible; a binary that was never built would turn the section
# into a silent skip, which is the failure mode ADR-0007 exists to prevent.
if ! as_builder env -u SUDO_USER cargo test -p daer-ebpf --test datapath --no-run \
        >"$logs/build-datapath.log" 2>&1; then
    bad "the datapath test binary did not build; see $logs/build-datapath.log"
    binary_datapath=""
else
    binary_datapath="$(ls -t target/debug/deps/datapath-* 2>/dev/null \
        | grep -v '\.d$' | head -n 1)"
    if [[ -z "$binary_datapath" ]]; then
        bad "no datapath test binary under target/debug/deps"
    else
        ok "binary: $binary_datapath"
    fi
fi

# Runs one test by name with root privileges, logs it, and reports pass/fail.
# `sudo` wraps the binary only — never cargo.
run_one() {
    local name="$1" log="$2" description="$3"
    if [[ -z "$binary" ]]; then
        skip "kernel-binary" "$description (no binary)"
        return
    fi
    if [[ ! -x "$binary" ]]; then
        bad "$description: $binary is not executable"
        return
    fi
    if "$binary" --include-ignored --nocapture --test-threads=1 "$name" >"$log" 2>&1 \
            && grep -q "test result: ok" "$log"; then
        ok "$description"
        if grep -qE "loaded [0-9]+ (maps|programs)" "$log"; then
            grep -E "loaded [0-9]+ (maps|programs)" "$log" | sed 's/^/       /'
        fi
        return 0
    fi
    bad "$description; see $log"
    # The first few lines that explain *why*. The escape strip is needed because cargo and
    # the test harness emit ANSI even into a file, and grepping those raw yields fragments.
    if command -v perl >/dev/null 2>&1; then
        perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$log" 2>/dev/null \
            | awk '/must load:|PermissionDenied|verifier|LoadError|panicked|attach|InvalidProgram|insn_off/ \
                   { print "       " $0; if (++n == 3) exit }'
    else
        awk '/must load:|PermissionDenied|verifier|LoadError|panicked|attach|InvalidProgram|insn_off/ \
             { print "       " $0; if (++n == 3) exit }' "$log"
    fi
    return 1
}

section "4. loading the object (this runs the verifier)"
run_one the_object_loads_and_verifies "$logs/load.log" "the object loaded and passed the verifier"

section "5. attaching to a real interface"
run_one a_tc_program_attaches_to_loopback "$logs/attach.log" "a tc program attached to lo"

section "6. the device pair and PARAM"
created_pair=0
if ip link show daer0 >/dev/null 2>&1; then
    ok "daer0 exists (left by a previous run; the daemon reuses it)"
elif ip link add daer0peer type veth peer name daer0 2>/dev/null; then
    ok "created daer0 <-> daer0peer"
    created_pair=1
else
    bad "cannot create a veth pair"
fi

if ip link show daer0 >/dev/null 2>&1; then
    ip link set daer0 up 2>/dev/null && ok "daer0 up" || bad "cannot bring daer0 up"
    ip link set daer0peer up 2>/dev/null && ok "daer0peer up" || bad "cannot bring daer0peer up"
    mac="$(cat /sys/class/net/daer0peer/address 2>/dev/null)"
    idx="$(cat /sys/class/net/daer0/ifindex 2>/dev/null)"
    [[ -n "$mac" ]] && ok "peer MAC $mac" || bad "cannot read the peer MAC"
    [[ -n "$idx" ]] && ok "device ifindex $idx" || bad "cannot read the ifindex"
fi

if [[ "$created_pair" == 1 ]]; then
    ip link del daer0 2>/dev/null && ok "removed the test pair"
fi

section "7. the in-kernel datapath cases (BPF_PROG_TEST_RUN)"
# Every case is a pktgen/setup/check triple in `ebpf/kern/tests/bpf_test.c`, compiled into
# `target/ebpf/datapath-test.o` and driven by `crates/daer-ebpf/tests/datapath.rs`. This is
# the only part of the suite that executes the datapath's own logic in the kernel.
if [[ -z "$binary_datapath" ]]; then
    skip "7" "no datapath test binary (run \`cargo xtask ebpf --tests\`)"
elif [[ ! -f target/ebpf/datapath-test.o ]]; then
    skip "7" "target/ebpf/datapath-test.o is missing (run \`cargo xtask ebpf --tests\`)"
else
    run_one every_datapath_case_passes "$logs/datapath.log" \
        "every in-kernel datapath case passed"
fi

section "summary"
if [[ "$failures" -eq 0 ]]; then
    printf '%s%sAll checks passed. The kernel datapath works on this machine.%s\n' \
        "$GREEN" "$BOLD" "$OFF"
    # A skip is still reported on the green path. Omitting it here would let a run that
    # proved nothing print the same line as one that proved everything (ADR-0007).
    if [[ "$skips" -gt 0 ]]; then
        printf '%s%d check(s) skipped — read the reasons above before treating this as full coverage.%s\n' \
            "$YELLOW" "$skips" "$OFF"
        if [[ -n "${DAER_REQUIRE:-}" ]]; then
            printf 'DAER_REQUIRE=%s was satisfied; raise it to make more skips fatal.\n' "$DAER_REQUIRE"
        else
            printf 'Set DAER_REQUIRE=<key,...> to make a skip fatal in CI.\n'
        fi
    else
        printf 'No check was skipped: every gate above ran and passed.\n'
    fi
    printf 'Logs: %s\n' "$logs"
    printf 'Next: %ssudo %s run -c /etc/daer/config.toml%s\n' "$BOLD" "$root/target/release/daer" "$OFF"
    exit 0
fi
printf '%s%s%d check(s) failed, %d skipped.%s\n' "$RED" "$BOLD" "$failures" "$skips" "$OFF"
printf 'Logs are in %s — send them along.\n' "$logs"
exit 1
