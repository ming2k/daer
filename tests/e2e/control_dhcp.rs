// SPDX-License-Identifier: AGPL-3.0-only

//! A real DHCP lease while `daer` owns the WAN.
//!
//! # The incident this exists for
//!
//! A host running `daer` lost its network after the DHCP lease expired. The daemon's WAN
//! egress hook captured the host's own DHCP broadcast, the kernel policy handed it to the
//! userspace relay, and the relay tried to re-originate `0.0.0.0:68 → 255.255.255.255:67`
//! as a connected UDP socket. That cannot work: the socket lacks `SO_BROADCAST`, the source
//! port is not 68, and the source address is not 0.0.0.0. The renewal never reached the
//! server, the lease expired, and the interface lost its address and default route.
//!
//! The unit and integration tests prove the pieces: the IPv4 LPM key matches the datapath's
//! `::ffff` convention, and the datapath C cases prove a DHCP broadcast is not redirected.
//! This test proves the same shape through a **real DHCP server and client** in separate
//! network namespaces, with a real `daer run` and the real datapath object.
//!
//! # The two tests
//!
//! * `the_dhcp_fixture_serves_a_lease_without_daer` is the fixture's own control: the
//!   netns/veth/dnsmasq/udhcpc wiring must produce a lease before any daemon is involved.
//!   Without it, a failure in the daemon test could just as well be a broken DHCP fixture.
//! * `a_dhcp_lease_is_acquired_while_daer_owns_the_wan` is the regression. The daemon runs
//!   with a **partitioned** policy (an IP rule followed by a domain rule), so the pre-fix
//!   behaviour is exactly the incident: the kernel prefix rules miss, the gate punts the
//!   DHCP broadcast, and no lease is acquired.
//!
//! # Privileges and skips
//!
//! This creates named network namespaces and a real veth pair, runs `dnsmasq` and
//! `busybox udhcpc`, and attaches the eBPF datapath. It is gated on `DAER_NETNS_TEST=1` and
//! skips with a named reason when the host cannot provide the tools or the capability. The
//! privileged `e2e-ingress` job sets the variable and fails on a `skipped: ` line, so a
//! missing tool cannot masquerade as coverage (ADR-0007).

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Address the DHCP server holds on its end of the veth.
const SERVER_ADDRESS: &str = "10.66.0.1";
/// The range dnsmasq offers. The client must land inside it.
const RANGE_START: &str = "10.66.0.10";
const RANGE_END: &str = "10.66.0.20";

/// Finds a fixture tool on `PATH` without assuming a package manager.
fn tool(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn gated() -> bool {
    if std::env::var_os("DAER_NETNS_TEST").is_none() {
        eprintln!(
            "skipping: set DAER_NETNS_TEST=1 in a disposable namespace; this test owns named \
             network namespaces and a veth pair"
        );
        return false;
    }
    true
}

/// Runs `ip` and folds stdout/stderr into the error.
fn ip(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|error| format!("cannot run `ip {}`: {error}", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "`ip {}` failed ({}): {}{}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// A named network namespace removed on drop.
struct Netns {
    name: String,
}

impl Netns {
    fn add(name: &str) -> Result<Self, String> {
        ip(&["netns", "add", name])?;
        Ok(Self {
            name: name.to_owned(),
        })
    }

    fn exec(&self, program: &Path) -> Command {
        let mut command = Command::new("ip");
        command.args(["netns", "exec", &self.name]).arg(program);
        command
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = ip(&["netns", "del", &self.name]);
    }
}

/// Runs one shell command inside a namespace.
fn shell_in(namespace: &str, script: &str) -> Result<(), String> {
    let output = Command::new("ip")
        .args(["netns", "exec", namespace, "sh", "-c", script])
        .output()
        .map_err(|error| format!("cannot run a shell in {namespace}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`sh -c {script:?}` in {namespace} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// The server and the daemon host, wired by one veth pair.
struct Fixture {
    server: Netns,
    daer: Netns,
    server_if: String,
    wan_if: String,
    server_child: Option<Child>,
    lease_log: PathBuf,
    script: PathBuf,
    directory: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Result<Self, String> {
        let pid = std::process::id();
        let server = Netns::add(&format!("daer-dhcp-srv-{tag}-{pid}"))?;
        let daer = Netns::add(&format!("daer-dhcp-cli-{tag}-{pid}"))?;
        // Two tests in this module may run in one process; the interface names must not
        // collide even if a runner ignores the nextest serial group. The tag is one byte,
        // so the name stays far below IFNAMSIZ.
        let tag_char = tag.chars().next().unwrap_or('x');
        let server_if = format!("ds{tag_char}{pid}");
        let wan_if = format!("dw{tag_char}{pid}");
        let directory = std::env::temp_dir().join(format!("daer-dhcp-{tag}-{pid}"));

        let result = (|| -> Result<(), String> {
            ip(&[
                "link", "add", &server_if, "type", "veth", "peer", "name", &wan_if,
            ])?;
            ip(&["link", "set", &server_if, "netns", &server.name])?;
            ip(&["link", "set", &wan_if, "netns", &daer.name])?;
            ip(&["-n", &server.name, "link", "set", "lo", "up"])?;
            ip(&["-n", &daer.name, "link", "set", "lo", "up"])?;
            ip(&[
                "-n",
                &server.name,
                "addr",
                "add",
                &format!("{SERVER_ADDRESS}/24"),
                "dev",
                &server_if,
            ])?;
            ip(&["-n", &server.name, "link", "set", &server_if, "up"])?;
            ip(&["-n", &daer.name, "link", "set", &wan_if, "up"])?;

            // The datapath checks these host-global prerequisites before it creates the
            // private ingress. They are per-netns, so writing them through `ip netns exec`
            // changes only the disposable daemon namespace, not the host.
            for (path, value) in [
                ("ipv4/ip_forward", "1"),
                ("ipv4/conf/all/forwarding", "1"),
                ("ipv4/conf/all/rp_filter", "0"),
                ("ipv4/conf/all/arp_filter", "0"),
            ] {
                shell_in(&daer.name, &format!("echo {value} > /proc/sys/net/{path}"))?;
            }
            if Path::new("/proc/sys/net/ipv6/conf/all/forwarding").exists() {
                shell_in(
                    &daer.name,
                    "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding",
                )?;
            }

            fs::create_dir_all(&directory)
                .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
            Ok(())
        })();

        if let Err(error) = result {
            // A veth that was created but not moved belongs to the host; deleting the
            // namespaces removes the halves that were moved, and this removes the rest.
            let _ = ip(&["link", "del", &server_if]);
            let _ = ip(&["link", "del", &wan_if]);
            return Err(error);
        }

        let lease_log = directory.join("lease");
        let script = directory.join("udhcpc.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 case \"$1\" in\n\
                   bound|renew) echo \"$1 $ip\" >> \"{}\" ;;\n\
                   leasefail) echo \"leasefail\" >> \"{}\" ;;\n\
                 esac\n",
                lease_log.display(),
                lease_log.display()
            ),
        )
        .map_err(|error| format!("cannot write {}: {error}", script.display()))?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot chmod {}: {error}", script.display()))?;

        Ok(Self {
            server,
            daer,
            server_if,
            wan_if,
            server_child: None,
            lease_log,
            script,
            directory,
        })
    }

    /// Starts a DHCP-only dnsmasq on the server end of the veth.
    fn start_server(&mut self) -> Result<(), String> {
        let dnsmasq = tool("dnsmasq").ok_or_else(|| "dnsmasq is not installed".to_owned())?;
        let leasefile = self.directory.join("dnsmasq.leases");
        let leasefile = leasefile.to_string_lossy().into_owned();
        let range = format!("{RANGE_START},{RANGE_END},255.255.255.0,300s");
        let interface = format!("--interface={}", self.server_if);
        let range = format!("--dhcp-range={range}");
        let leasefile = format!("--dhcp-leasefile={leasefile}");
        let mut command = self.server.exec(&dnsmasq);
        command.args([
            "--no-daemon",
            "--keep-in-foreground",
            "--conf-file=/dev/null",
            "--user=root",
            "--port=0",
            "--bind-interfaces",
            &interface,
            "--except-interface=lo",
            "--dhcp-authoritative",
            &range,
            "--dhcp-option=3,10.66.0.1",
            "--dhcp-option=6,10.66.0.1",
            "--no-resolv",
            "--no-hosts",
            &leasefile,
            "--log-dhcp",
        ]);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot spawn dnsmasq: {error}"))?;
        std::thread::sleep(Duration::from_millis(250));
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot poll dnsmasq: {error}"))?
        {
            return Err(format!("dnsmasq exited before the client ran: {status}"));
        }
        self.server_child = Some(child);
        Ok(())
    }

    /// Runs `busybox udhcpc` in the daemon namespace and waits for a bound/renew event.
    fn acquire(&mut self) -> Result<String, String> {
        let busybox =
            tool("busybox").ok_or_else(|| "busybox (udhcpc) is not installed".to_owned())?;
        let _ = fs::remove_file(&self.lease_log);
        let script = self.script.to_string_lossy().into_owned();
        let mut command = self.daer.exec(&busybox);
        command.args([
            "udhcpc",
            "-i",
            &self.wan_if,
            "-f",
            "-q",
            "-n",
            "-t",
            "20",
            "-T",
            "2",
            "-s",
            &script,
        ]);
        command
            .env("LEASE_LOG", &self.lease_log)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot spawn udhcpc: {error}"))?;

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let log = fs::read_to_string(&self.lease_log).unwrap_or_default();
            if let Some(line) = log
                .lines()
                .find(|line| line.starts_with("bound ") || line.starts_with("renew "))
            {
                let line = line.to_owned();
                let _ = child.kill();
                let _ = child.wait();
                return Ok(line);
            }
            if log.contains("leasefail") {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("udhcpc reported leasefail; log: {log:?}"));
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("cannot poll udhcpc: {error}"))?
            {
                let _ = child.wait();
                return Err(format!(
                    "udhcpc exited with {status} without a lease; log: {log:?}"
                ));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("no DHCP lease within 20s; log: {log:?}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Starts `daer run` with the real datapath in the daemon namespace.
    fn start_daemon(&self) -> Result<Daemon, String> {
        let object = crate::common::workspace_path("target/ebpf/datapath.bpf.o");
        if !object.is_file() {
            return Err(format!(
                "{} is missing; run `cargo xtask ebpf`",
                object.display()
            ));
        }
        let config = self.directory.join("daer.toml");
        fs::write(
            &config,
            format!(
                "schema = 6\n\
                 wan-interface = [\"{}\"]\n\
                 disable-waiting-network = true\n\
                 log-level = \"debug\"\n\
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
                 match = \"dip(10.66.0.0/24)\"\n\
                 action = \"direct\"\n\
                 \n\
                 [[routing.rule]]\n\
                 name = \"multicast\"\n\
                 match = \"dip(224.0.0.0/3)\"\n\
                 action = \"direct\"\n\
                 \n\
                 [[routing.rule]]\n\
                 name = \"named\"\n\
                 match = \"domain(example.com)\"\n\
                 action = \"direct\"\n",
                self.wan_if
            ),
        )
        .map_err(|error| format!("cannot write {}: {error}", config.display()))?;

        let status_socket = self.directory.join("status.sock");
        let state = self.directory.join("state.json");
        let admin_socket = self.directory.join("admin.sock");
        let elections = self.directory.join("elections.json");
        let binary = crate::common::daer();
        let mut command = self.daer.exec(&binary);
        command
            .args(["run", "--config"])
            .arg(&config)
            .args(["--object"])
            .arg(&object)
            .env("DAER_STATUS_SOCKET", &status_socket)
            .env("DAER_STATUS_STATE", &state)
            .env("DAER_ADMIN_SOCKET", &admin_socket)
            .env("DAER_ELECTION_STATE", &elections)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot spawn daer: {error}"))?;

        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let stdout = child.stdout.take().expect("daemon stdout is piped");
        let stderr = child.stderr.take().expect("daemon stderr is piped");
        for stream in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr) as Box<dyn std::io::Read + Send>,
        ] {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    log.lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .push(line);
                }
            });
        }
        let mut daemon = Daemon { child, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if daemon.contains("datapath attached") {
                return Ok(daemon);
            }
            let log = daemon.snapshot();
            if log.iter().any(|line| {
                line.contains("cannot attach")
                    || line.contains("cannot prepare the private ingress")
                    || line.contains("host sysctl")
                    || line.contains("forwarding")
                    || line.contains("has ARPHRD type")
                    || line.contains("Operation not permitted")
                    || line.contains("panicked")
            }) {
                return Err(format!(
                    "the daemon could not attach here; log:\n{}",
                    log.join("\n")
                ));
            }
            if daemon.exited()? {
                return Err(format!(
                    "the daemon exited before attaching; log:\n{}",
                    log.join("\n")
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the daemon did not attach within 30s; log:\n{}",
                    log.join("\n")
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.server_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The daemon process plus its `debug` log.
struct Daemon {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    fn snapshot(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn contains(&self, needle: &str) -> bool {
        self.log
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .any(|line| line.contains(needle))
    }

    fn exited(&mut self) -> Result<bool, String> {
        Ok(self
            .child
            .try_wait()
            .map_err(|error| format!("cannot poll the daemon: {error}"))?
            .is_some())
    }

    /// Sends `SIGTERM` and waits for the daemon's own bounded shutdown.
    fn stop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The control: the namespace/veth/dnsmasq/udhcpc fixture itself must produce a lease.
#[test]
fn the_dhcp_fixture_serves_a_lease_without_daer() {
    if !gated() {
        return;
    }
    let mut fixture = match Fixture::new("fixture") {
        Ok(fixture) => fixture,
        Err(reason) => {
            eprintln!("skipped: {reason}");
            return;
        }
    };
    if let Err(reason) = fixture.start_server() {
        eprintln!("skipped: {reason}");
        return;
    }
    let lease = match fixture.acquire() {
        Ok(lease) => lease,
        Err(reason) => {
            eprintln!("skipped: the DHCP fixture did not produce a lease: {reason}");
            return;
        }
    };
    assert!(
        lease.starts_with("bound 10.66.0.") || lease.starts_with("renew 10.66.0."),
        "the fixture must hand out an address in the configured range, got {lease:?}"
    );
}

/// The regression: a real DHCP client must get a lease while `daer` owns the WAN.
#[test]
fn a_dhcp_lease_is_acquired_while_daer_owns_the_wan() {
    if !gated() {
        return;
    }
    let mut fixture = match Fixture::new("daemon") {
        Ok(fixture) => fixture,
        Err(reason) => {
            eprintln!("skipped: {reason}");
            return;
        }
    };
    if let Err(reason) = fixture.start_server() {
        eprintln!("skipped: {reason}");
        return;
    }
    let mut daemon = match fixture.start_daemon() {
        Ok(daemon) => daemon,
        Err(reason) => {
            eprintln!("skipped: {reason}");
            return;
        }
    };
    let lease = match fixture.acquire() {
        Ok(lease) => lease,
        Err(reason) => {
            panic!(
                "the DHCP lease must succeed through daer; {reason}; daemon log:\n{}",
                daemon.snapshot().join("\n")
            );
        }
    };
    assert!(
        lease.starts_with("bound 10.66.0.") || lease.starts_with("renew 10.66.0."),
        "the client must receive an address in the configured range, got {lease:?}"
    );
    assert!(
        daemon.contains("datapath.policy_partitioned"),
        "the regression only reproduces with a partitioned policy; daemon log:\n{}",
        daemon.snapshot().join("\n")
    );
    assert!(
        !daemon
            .snapshot()
            .iter()
            .any(|line| { line.contains("flow.datagram_session_failed") && line.contains(":68") }),
        "DHCP must not reach the userspace datagram relay; daemon log:\n{}",
        daemon.snapshot().join("\n")
    );
    daemon.stop();
}
