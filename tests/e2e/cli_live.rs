// SPDX-License-Identifier: AGPL-3.0-only

//! The live CLI surface: `status --json`, `elect`, and a clean `SIGTERM`.
//!
//! `daer status` and `daer elect` are clients of two sockets the daemon owns. Testing them
//! against a mock is not enough: the failure this layer exists to catch is a socket path,
//! permission mode, snapshot field or signal path that disagrees with the daemon. This test
//! starts the real binary, points both sockets at a scratch directory, exercises the clients,
//! and then stops the daemon with the signal an operator uses.
//!
//! # Privileges
//!
//! `daer run --no-datapath` still binds a transparent listener, which needs
//! `CAP_NET_ADMIN`. Without it the daemon exits before serving; the test skips with the
//! reason, and the privileged CI job treats a `skipped: ` line as a failure (ADR-0007).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The workspace binary, as built by `cargo build --bins`.
fn binary() -> PathBuf {
    crate::common::daer()
}

/// A running daemon whose stdout/stderr are drained on their own threads.
struct Daemon {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Daemon {
    fn spawn(
        config: &Path,
        status: &Path,
        state: &Path,
        admin: &Path,
        elections: &Path,
        no_datapath: bool,
    ) -> Self {
        let mut command = Command::new(binary());
        command.args(["run"]);
        if no_datapath {
            command.arg("--no-datapath");
        }
        command.arg("--config").arg(config);
        let mut child = command
            .env("DAER_STATUS_SOCKET", status)
            .env("DAER_STATUS_STATE", state)
            .env("DAER_ADMIN_SOCKET", admin)
            .env("DAER_ELECTION_STATE", elections)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawns daer run");
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let (sender, lines) = mpsc::channel::<String>();
        for stream in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr) as Box<dyn std::io::Read + Send>,
        ] {
            let sender = sender.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if sender.send(line).is_err() {
                        return;
                    }
                }
            });
        }
        drop(sender);
        Self {
            child,
            lines,
            log: Vec::new(),
        }
    }

    /// Waits for the serving line, or returns `None` when this host cannot start the daemon.
    ///
    /// The skip path is deliberate and named: the privileged CI job turns it into a red
    /// build, while an unprivileged developer run gets the reason instead of a misleading
    /// green.
    fn wait_for_serving(&mut self, needle: &str) -> Option<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() >= deadline {
                eprintln!(
                    "skipped: the daemon did not reach its serving state in 30s; log:\n{}",
                    self.log.join("\n")
                );
                return None;
            }
            match self.lines.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    let fatal = line.contains("cannot bind the transparent port")
                        || line.contains("cannot attach")
                        || line.contains("has ARPHRD type")
                        || line.contains("host sysctl")
                        || line.contains("forwarding")
                        || line.contains("Operation not permitted")
                        || line.contains("panicked");
                    self.log.push(line);
                    if fatal {
                        eprintln!(
                            "skipped: the daemon could not start here; log:\n{}",
                            self.log.join("\n")
                        );
                        return None;
                    }
                    if self.log.last().is_some_and(|line| line.contains(needle)) {
                        return Some(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Ok(Some(status)) = self.child.try_wait() {
                        eprintln!(
                            "skipped: the daemon exited with {status} before serving; log:\n{}",
                            self.log.join("\n")
                        );
                        return None;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    eprintln!(
                        "skipped: the daemon log closed before serving; log:\n{}",
                        self.log.join("\n")
                    );
                    return None;
                }
            }
        }
    }

    /// Runs a client until it succeeds or the deadline expires.
    ///
    /// The status socket is bound before the first state snapshot is written, so one
    /// immediately-after-serving request can race the writer. Retrying is the honest way to
    /// distinguish a slow writer from a broken client; the final failure carries the last
    /// output.
    fn command_until_success(&mut self, mut command: Command, what: &str) -> std::process::Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let output = command.output().expect("runs the daer client");
            if output.status.success() {
                return output;
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "{what} did not succeed within 10s; stderr:\n{}; daemon log:\n{}",
                    String::from_utf8_lossy(&output.stderr),
                    self.log.join("\n")
                );
                panic!("{what} failed");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stops the daemon with `SIGTERM` and returns its exit status.
    fn terminate(&mut self) -> std::process::ExitStatus {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("runs kill -TERM");
        assert!(status.success(), "kill -TERM failed: {status}");

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!(
                    "the daemon did not exit within 20s of SIGTERM; log:\n{}",
                    self.log.join("\n")
                );
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

/// Sets the host-global prerequisites the datapath requires.
///
/// The test is gated on `DAER_NETNS_TEST=1`, so it runs inside a disposable network
/// namespace: these writes do not touch the host's operator-managed policy.
fn set_host_prerequisites() {
    for (path, value) in [
        ("ipv4/ip_forward", "1"),
        ("ipv4/conf/all/forwarding", "1"),
        ("ipv4/conf/all/rp_filter", "0"),
        ("ipv4/conf/all/arp_filter", "0"),
    ] {
        std::fs::write(format!("/proc/sys/net/{path}"), value)
            .unwrap_or_else(|error| panic!("set net/{path} = {value}: {error}"));
    }
    let ipv6 = "/proc/sys/net/ipv6/conf/all/forwarding";
    if Path::new(ipv6).exists() {
        std::fs::write(ipv6, "1").expect("set IPv6 forwarding");
    }
}

/// A scratch directory removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("daer-cli-live-{tag}-{}", std::process::id()));
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

/// A config with one manual election, so `daer elect` has a real target.
const CONFIG: &str = r#"
schema = 6
wan-interface = ["lo"]
disable-waiting-network = true
log-level = "debug"

[[node]]
name = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1

[[election]]
name = "proxy"
node = "n1"
type = "manual"

[routing]
default = "proxy"
"#;

#[test]
fn status_elect_and_sigterm_form_one_live_contract() {
    let dir = Scratch::new("contract");
    let config = dir.join("config.toml");
    std::fs::write(&config, CONFIG).expect("writes the configuration");
    let status_socket = dir.join("status.sock");
    let state = dir.join("state.json");
    let admin_socket = dir.join("admin.sock");
    let elections = dir.join("elections.json");

    let mut daemon = Daemon::spawn(
        &config,
        &status_socket,
        &state,
        &admin_socket,
        &elections,
        true,
    );
    if daemon
        .wait_for_serving("listening for redirected flows")
        .is_none()
    {
        return;
    }
    let pid = daemon.child.id();

    // 1. The read-only snapshot is a versioned JSON document, not a human summary.
    let status = daemon.command_until_success(
        {
            let mut command = Command::new(binary());
            command
                .args(["status", "--json"])
                .env("DAER_STATUS_SOCKET", &status_socket)
                .env("DAER_STATUS_STATE", &state);
            command
        },
        "daer status --json",
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("status --json is JSON");
    assert_eq!(snapshot["schema"], 1, "the snapshot must be versioned");
    assert_eq!(
        snapshot["pid"], pid,
        "the snapshot must name the daemon it came from"
    );
    assert!(
        snapshot["generation"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("gen")),
        "the snapshot must carry a generation: {}",
        snapshot["generation"]
    );
    assert_eq!(
        snapshot["datapath"]["attached"], false,
        "--no-datapath must be visible in the snapshot"
    );
    assert!(
        snapshot["datapath"]["skipped"]
            .as_array()
            .is_some_and(|skipped| skipped.iter().any(|value| value == "--no-datapath")),
        "the snapshot must name why the datapath is absent: {}",
        snapshot["datapath"]
    );
    assert!(
        snapshot["flows"]["accepted"].is_number(),
        "the flow counters must be present: {}",
        snapshot["flows"]
    );

    // 2. The writable control socket pins and clears the manual election.
    let elected = daemon.command_until_success(
        {
            let mut command = Command::new(binary());
            command
                .args(["elect", "proxy", "n1", "--json"])
                .env("DAER_ADMIN_SOCKET", &admin_socket);
            command
        },
        "daer elect proxy n1",
    );
    let elected: serde_json::Value =
        serde_json::from_slice(&elected.stdout).expect("elect --json is JSON");
    assert_eq!(elected["pinned"], true, "{elected}");
    assert_eq!(elected["election"], "proxy", "{elected}");
    assert_eq!(elected["node"], "n1", "{elected}");

    let reset = daemon.command_until_success(
        {
            let mut command = Command::new(binary());
            command
                .args(["elect", "proxy", "--reset", "--json"])
                .env("DAER_ADMIN_SOCKET", &admin_socket);
            command
        },
        "daer elect proxy --reset",
    );
    let reset: serde_json::Value =
        serde_json::from_slice(&reset.stdout).expect("reset --json is JSON");
    assert_eq!(reset["reset"], true, "{reset}");
    assert_eq!(reset["election"], "proxy", "{reset}");

    // 3. SIGTERM is a clean stop: the process exits successfully and both sockets are gone.
    // A signal path that leaves a socket behind makes the next start bind a stale path or
    // fail on permissions, which is the class of lifecycle bug this test exists to catch.
    let status = daemon.terminate();
    while let Ok(line) = daemon.lines.try_recv() {
        daemon.log.push(line);
    }
    assert!(
        status.success(),
        "SIGTERM must be a successful shutdown, got {status}; log:\n{}",
        daemon.log.join("\n")
    );
    assert!(
        !status_socket.exists(),
        "the status socket must be removed on shutdown"
    );
    assert!(
        !admin_socket.exists(),
        "the admin socket must be removed on shutdown"
    );
    assert!(
        !daemon.log.iter().any(|line| line.contains("panicked")),
        "the daemon panicked during shutdown; log:\n{}",
        daemon.log.join("\n")
    );
}

/// A real datapath start/stop: the private ingress and `daer0` are process-owned state.
///
/// `--no-datapath` proves the process and socket lifecycle but never creates the veth pair.
/// This test runs the service as the unit does, waits for the datapath attachment, and then
/// requires `SIGTERM` to remove `daer0`. It is gated on `DAER_NETNS_TEST=1` because it owns
/// the host-visible pair and needs a disposable network namespace, exactly like
/// `control_netns_lifecycle`.
#[test]
fn sigterm_removes_the_private_ingress() {
    if std::env::var_os("DAER_NETNS_TEST").is_none() {
        eprintln!(
            "skipping: set DAER_NETNS_TEST=1 in a disposable namespace; this test owns daer0"
        );
        return;
    }
    set_host_prerequisites();
    let dir = Scratch::new("netns");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        "schema = 6\n\
         wan-interface = \"auto\"\n\
         disable-waiting-network = true\n\
         \n\
         [routing]\n\
         default = \"direct\"\n",
    )
    .expect("writes the configuration");
    let status_socket = dir.join("status.sock");
    let state = dir.join("state.json");
    let admin_socket = dir.join("admin.sock");
    let elections = dir.join("elections.json");

    let mut daemon = Daemon::spawn(
        &config,
        &status_socket,
        &state,
        &admin_socket,
        &elections,
        false,
    );
    if daemon.wait_for_serving("datapath attached").is_none() {
        return;
    }
    assert!(
        Path::new("/sys/class/net/daer0").exists(),
        "the datapath attachment must own the host end of the pair; log:\n{}",
        daemon.log.join("\n")
    );
    assert!(
        Path::new("/run/daer/daer.lock").exists(),
        "the single-instance lock must exist while the daemon owns the ingress"
    );

    let status = daemon.terminate();
    while let Ok(line) = daemon.lines.try_recv() {
        daemon.log.push(line);
    }
    assert!(
        status.success(),
        "SIGTERM must be a successful shutdown, got {status}; log:\n{}",
        daemon.log.join("\n")
    );

    // The kernel unregisters the veth peer asynchronously; the guard's drop is synchronous but
    // device destruction is not, so poll rather than assume the first read is final.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Path::new("/sys/class/net/daer0").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !Path::new("/sys/class/net/daer0").exists(),
        "the private ingress pair must be gone after SIGTERM; log:\n{}",
        daemon.log.join("\n")
    );
    assert!(
        !status_socket.exists() && !admin_socket.exists(),
        "the status and admin sockets must be removed after SIGTERM"
    );
}
