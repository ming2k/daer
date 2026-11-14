// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces ADR-0029: the unprivileged gate needs no privilege and changes nothing.
//!
//! The claim `--dry-run` makes is not "it usually exits early". It is that a dry run performs
//! **no** `bind()`, creates no device, writes no sysctl, installs no route and makes no
//! `bpf()` call — on an unprivileged machine, from a clean state. That is a claim about
//! behaviour, so it is asserted by behaviour rather than by reading the source.
//!
//! # Why the state is measured, not assumed
//!
//! A test that runs `--dry-run` and checks the exit code proves nothing: the previous
//! implementation also exited zero, after it had bound a port, created a veth pair, written
//! `/proc/sys/net/ipv4/conf/daer0peer/rp_filter` and installed a policy route. The assertions
//! below therefore compare the observable system state — the device pair, the `fwmark` rule,
//! the routing table — before and after, and require it unchanged.

use std::path::{Path, PathBuf};
use std::process::Command;

fn daer() -> Command {
    Command::new(crate::common::daer())
}

fn workspace_root() -> PathBuf {
    crate::common::workspace_root()
}

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    /// `tag` must distinguish every test that uses this helper.
    ///
    /// `std::process::id()` does not: cargo runs a test binary's tests as threads of one
    /// process, so two tests that pass the same tag share a path, and `Drop` in the first
    /// deletes the directory the second is still using. That produced a failure which named
    /// "failed to read <dir>: No such file or directory" and looked like a preflight bug.
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("daer-preflight-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creates the scratch directory");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A minimal configuration that needs no network and no rule provider.
fn config(tag: &str) -> (Scratch, PathBuf) {
    let dir = Scratch::new(tag);
    let path = dir.join("preflight.toml");
    std::fs::write(&path, "schema = 6\n\nwan-interface = \"auto\"\n")
        .expect("writes the configuration");
    (dir, path)
}

/// Whether a network device exists, without creating it.
fn device_exists(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}")).exists()
}

/// The `ip` argument vector.
///
/// Returns `Option` because `ip` may be absent or the subcommand unsupported — but the
/// caller must distinguish "two identical `None`s" from "two identical readings". An earlier
/// version compared the `Option`s directly, so on a machine without `ip` the assertion
/// `None == None` passed without ever observing the system: a negative control that cannot
/// fail is not a control (ADR-0007).
fn ip(args: &[&str]) -> Option<String> {
    let output = Command::new("ip").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Compares a before/after reading, refusing to pass when the reading was never taken.
fn unchanged(before: &Option<String>, after: Option<String>, what: &str) {
    match (before, after) {
        (Some(before), Some(after)) => assert_eq!(
            before, &after,
            "a dry run must not change {what} (before: {before:?}, after: {after:?})"
        ),
        // `ip` is missing or the subcommand is unsupported. That is a skip with a reason,
        // not a pass: there is no observation to compare.
        (None, _) | (_, None) => eprintln!(
            "skipped: cannot read {what} on this machine (is `ip` installed?);              the assertion for it did not run"
        ),
    }
}

#[test]
fn a_dry_run_changes_no_system_state() {
    let object = workspace_root().join("target/ebpf/datapath.bpf.o");
    if !object.is_file() {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    }
    let (_dir, config) = config("state-changes");

    let devices_before = (device_exists("daer0"), device_exists("daer0peer"));
    // The `fwmark` policy route the real run installs. Reading it is itself unprivileged.
    let rule_before = ip(&["rule", "show"]);
    let route_before = ip(&["route", "show", "table", "2023"]);

    let output = daer()
        .args(["run", "--config"])
        .arg(&config)
        .arg("--object")
        .arg(&object)
        .arg("--dry-run")
        .output()
        .expect("runs the daemon");

    assert!(
        output.status.success(),
        "a dry run must succeed without privileges; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let devices_after = (device_exists("daer0"), device_exists("daer0peer"));
    assert_eq!(
        devices_before, devices_after,
        "a dry run must not create or remove the device pair"
    );
    unchanged(
        &rule_before,
        ip(&["rule", "show"]),
        "the policy routing rules",
    );
    unchanged(
        &route_before,
        ip(&["route", "show", "table", "2023"]),
        "the fwmark routing table",
    );
}

#[test]
fn a_dry_run_reports_the_object_and_the_privilege_boundary() {
    let object = workspace_root().join("target/ebpf/datapath.bpf.o");
    if !object.is_file() {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    }
    let (_dir, config) = config("state-report");

    let output = daer()
        .args(["run", "--config"])
        .arg(&config)
        .arg("--object")
        .arg(&object)
        .arg("--dry-run")
        .output()
        .expect("runs the daemon");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The report has to say what would happen, or the gate is decorative.
    assert!(
        log.contains("nothing is bound, created or attached"),
        "the dry run must state that it changed nothing; log:\n{log}"
    );
    assert!(
        log.contains("datapath object is valid"),
        "the dry run must validate the object; log:\n{log}"
    );
    assert!(
        log.contains("kernel policy:"),
        "the dry run must report the kernel tier (ADR-0005/ADR-0011); log:\n{log}"
    );

    // On an unprivileged box the boundary must be named here, not discovered later as
    // "failed to create map 'daer_ifindex_map'" from the attachment code.
    if daer_ebpf_capabilities_missing() {
        assert!(
            log.contains("the privileged phase would not run here"),
            "an unprivileged dry run must name the missing capability; log:\n{log}"
        );
    }
}

/// Whether this process lacks a capability the preflight requires.
fn daer_ebpf_capabilities_missing() -> bool {
    let effective = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("CapEff:"))
                .and_then(|line| line["CapEff:".len()..].trim().parse::<u64>().ok())
        })
        .unwrap_or(0);
    let required = (1 << 39) | (1 << 38) | (1 << 21) | (1 << 12);
    // CAP_BPF | CAP_PERFMON | CAP_SYS_ADMIN | CAP_NET_ADMIN
    effective & required != required
}

#[test]
fn check_rejects_an_object_whose_func_info_drifted() {
    let object = workspace_root().join("target/ebpf/datapath.bpf.o");
    if !object.is_file() {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    }
    let (_dir, config) = config("state-funcinfo");

    // Reproduce the production failure by renaming a section to one `aya` does not parse,
    // keeping the byte length so the ELF stays structurally valid. `daer check --object`
    // must reject it: the first `func_info` record of that program then sits at instruction
    // 3, which is exactly the `nonzero insn_off 3` the kernel reported before `daer.service`
    // crash-looped.
    let bytes = std::fs::read(&object).expect("reads the object");
    let from = b"classifier/wan_ingress_l2";
    let to = b"tc/xxxxxxx/wan_ingress_l2";
    assert_eq!(from.len(), to.len(), "the replacement must keep the length");
    let Some(at) = bytes.windows(from.len()).position(|window| window == from) else {
        panic!("the object does not contain the section under test");
    };
    let mut broken = bytes.clone();
    broken[at..at + from.len()].copy_from_slice(to);

    let dir = Scratch::new("funcinfo");
    let broken_path = dir.join("broken.o");
    std::fs::write(&broken_path, &broken).expect("writes the broken object");

    let good = daer()
        .args(["check", "--config"])
        .arg(&config)
        .arg("--object")
        .arg(&object)
        .output()
        .expect("runs the check");
    assert!(
        good.status.success(),
        "the good object must pass; stderr:\n{}",
        String::from_utf8_lossy(&good.stderr)
    );

    let bad = daer()
        .args(["check", "--config"])
        .arg(&config)
        .arg("--object")
        .arg(&broken_path)
        .output()
        .expect("runs the check");
    assert!(
        !bad.status.success(),
        "an object with a drifted func_info must fail the gate"
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&bad.stdout),
        String::from_utf8_lossy(&bad.stderr)
    );
    assert!(
        log.contains("instruction 3") || log.contains("func_info"),
        "the failure must name the func_info invariant; log:\n{log}"
    );
}

/// A dry run must load the same rule-provider pool the daemon loads.
///
/// # The defect this pins
///
/// `run --dry-run` called `RouterOptions::for_config` without `.with_rule_providers(...)`,
/// so the exact production configuration resolved by `daer check` and `daer route` failed
/// with `in 'rule-set(private-ips)': unknown rule set: private-ips`. The daemon then loaded
/// it normally, which is the [INV-LOADER-01] divergence this test makes impossible to
/// reintroduce: the dry run, the deployment gate, and the route diagnostic all consume the
/// same provider pool.
#[test]
fn a_dry_run_resolves_file_rule_sets_like_check_and_route() {
    let dir = Scratch::new("dry-run-provider");

    // A real DRB artifact, compiled by the producer binary. A hand-written file would test
    // the test's idea of the format, not the format the operator installs.
    let rules = dir.join("private.rules");
    std::fs::write(&rules, "---\nname: private\n---\n10.0.0.0/8\n")
        .expect("writes the rule source");
    let drb = dir.join("private.drb");
    let compile = crate::common::daer_drb_cmd()
        .args([
            "compile",
            rules.to_str().expect("utf-8 rule path"),
            "-o",
            drb.to_str().expect("utf-8 drb path"),
        ])
        .status()
        .expect("runs daer-drb compile");
    assert!(compile.success(), "daer-drb compile must succeed");

    let config = dir.join("config.toml");
    let text = format!(
        "schema = 6\n\
         wan-interface = [\"lo\"]\n\
         disable-waiting-network = true\n\
         \n\
         [[rule-set]]\n\
         name = \"private\"\n\
         type = \"file\"\n\
         path = {path:?}\n\
         \n\
         [routing]\n\
         default = \"direct\"\n\
         \n\
         [[routing.rule]]\n\
         name = \"private\"\n\
         match = \"rule-set(private)\"\n\
         action = \"direct\"\n",
        path = drb.display().to_string()
    );
    std::fs::write(&config, text).expect("writes the configuration");

    // No object and no datapath: this test is about the loader, not the kernel. It must run
    // on an unprivileged machine without `cargo xtask ebpf` having produced an artifact.
    let dry_run = daer()
        .args(["run", "--dry-run", "--no-datapath", "--config"])
        .arg(&config)
        .output()
        .expect("runs daer run --dry-run");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&dry_run.stdout),
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert!(
        dry_run.status.success(),
        "a dry run must resolve the file-backed rule set; log:\n{log}"
    );
    assert!(log.contains("configuration compiles"), "log:\n{log}");
    assert!(
        log.contains("rules=1"),
        "the generation must contain the rule; log:\n{log}"
    );
    assert!(
        log.contains("kernel policy: equivalent"),
        "an all-IP rule set must publish an equivalent kernel policy; log:\n{log}"
    );

    let check = daer()
        .args(["check", "--config"])
        .arg(&config)
        .args(["--object", "none"])
        .output()
        .expect("runs daer check");
    assert!(
        check.status.success(),
        "check must accept the same configuration; stderr:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check_log = format!(
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(
        check_log.contains("kernel policy: equivalent"),
        "check must report the same kernel tier as the dry run; log:\n{check_log}"
    );

    let route = daer()
        .args(["route", "--config"])
        .arg(&config)
        .args(["--source", "10.0.0.1:1234", "10.1.2.3:80"])
        .output()
        .expect("runs daer route");
    let route_log = format!(
        "{}{}",
        String::from_utf8_lossy(&route.stdout),
        String::from_utf8_lossy(&route.stderr)
    );
    assert!(
        route.status.success(),
        "the file-backed rule must route successfully; log:\n{route_log}"
    );
    assert!(
        route_log.contains("outbound   : direct"),
        "10.1.2.3 must be direct through the compiled range; log:\n{route_log}"
    );
}

/// A partitioned policy must be reported as partitioned, not as a full deferral.
///
/// The old dry-run message said "every flow is handed to the control plane" whenever the
/// kernel policy was not provably equivalent. With a bug that made every IPv4 prefix miss,
/// that message was accidentally true, so the output could not distinguish the intended
/// userspace relay hop for a domain suffix from a data-path failure for an entire address
/// family. The three-state report is what makes the difference visible.
#[test]
fn a_dry_run_reports_a_partitioned_policy_as_partitioned() {
    let dir = Scratch::new("dry-run-tier");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        "schema = 6\n\
         wan-interface = [\"lo\"]\n\
         disable-waiting-network = true\n\
         \n\
         [routing.sniff]\n\
         enabled = true\n\
         timeout = \"30ms\"\n\
         \n\
         [routing]\n\
         default = \"direct\"\n\
         \n\
         [[routing.rule]]\n\
         name = \"private\"\n\
         match = \"dip(10.0.0.0/8)\"\n\
         action = \"direct\"\n\
         \n\
         [[routing.rule]]\n\
         name = \"named\"\n\
         match = \"domain(example.com)\"\n\
         action = \"direct\"\n",
    )
    .expect("writes the configuration");

    let output = daer()
        .args(["run", "--dry-run", "--no-datapath", "--config"])
        .arg(&config)
        .output()
        .expect("runs daer run --dry-run");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "dry run failed; log:\n{log}");
    assert!(
        log.contains("kernel policy: partitioned"),
        "the IP rule before the domain boundary must be reported as in-kernel; log:\n{log}"
    );
    assert!(
        !log.contains("kernel policy: full deferral"),
        "a partitioned policy is not a full deferral; log:\n{log}"
    );
}
