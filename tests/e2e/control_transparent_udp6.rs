// SPDX-License-Identifier: AGPL-3.0-only

//! The IPv6 UDP transparent path, end to end, with a fixture that can actually fail.
//!
//! # Why this test is separate
//!
//! The in-order IPv4 UDP test in `transparent.rs` documents that `TPROXY` needs a datagram
//! whose ingress interface is not `lo`; a single-namespace fixture cannot provide one. This
//! test owns the full topology:
//!
//! ```text
//!   client ns                         host ns                         origin ns
//!   fd00:1::2 ── veth cc/hc ──▶ PREROUTING ── tproxy ──▶ daemon ──▶ fd00:2::2
//!                    ▲             │                                │
//!                    └──── reply ───┴────── local output ────────────┘
//! ```
//!
//! The client and origin are in separate network namespaces, so the client's datagram enters
//! the host on a real veth. The daemon is in the host namespace, exactly like the userspace
//! data-path tests. The redirect, policy route, and reply path are the same ones a deployment
//! installs.
//!
//! # Falsifiers
//!
//! * The origin's body is a per-run nonce, so a direct client-to-origin exchange cannot
//!   satisfy it.
//! * Before the daemon starts, the same client datagram must **not** get a reply: the tproxy
//!   rule points at a closed port. That is the negative control.
//! * After the daemon starts, the nonce must return **and** `datagram_stats().to_client()`
//!   must advance. A reply that bypassed the relay cannot satisfy both.
//! * Cleanup removes both namespaces, both veths, the nft table, the policy rule/route and
//!   the saved forwarding sysctl, so a failure does not strand the host in a redirected
//!   state.
//!
//! # Environment gating
//!
//! The test skips with an explicit reason when the host cannot create network namespaces or
//! lacks `nft`. `scripts/verify/e2e-check.sh` runs it privileged and
//! `DAER_REQUIRE=3-udp6` makes a skip a CI failure. A capability is a skip; a failure after
//! the probe is a real test failure, not a skip.
//!
//! For a disposable local run:
//!
//! ```sh
//! unshare -Urnm sh -c 'mount -t tmpfs tmpfs /run/netns; \
//!   cargo test -p daer-control --test transparent_udp6 -- --nocapture'
//! ```

use std::io;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use daer_control::{Daemon, RouterOptions};

/// The daemon's own socket mark. The redirect rule excludes it so the relay's outbound leg
/// to the origin is not captured again.
const SOCKET_MARK: u32 = 0x64616572;
/// The mark the tproxy rule gives the intercepted datagram.
const TPROXY_MARK: &str = "0x6d61";
const TPROXY_MARK_SPEC: &str = "0x6d61/0xffff";
const POLICY_TABLE: &str = "2024";

const CLIENT_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 2);
const CLIENT_HOST_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);
const ORIGIN_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 2);
const ORIGIN_HOST_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 1);
const ORIGIN_PORT: u16 = 18_082;

/// Runs one command, returning its stderr on failure.
fn run(args: &[&str]) -> Result<(), String> {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|error| format!("cannot run {}: {error}", args[0]))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "`{}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn nft(args: &[&str]) -> Result<(), String> {
    let mut command = vec!["nft"];
    command.extend_from_slice(args);
    run(&command)
}

/// Reads a link's MAC as `ip -o link` spells it.
fn link_mac(namespace: Option<&str>, link: &str) -> String {
    let mut command = Command::new("ip");
    if let Some(namespace) = namespace {
        command.args(["-n", namespace]);
    }
    let output = command
        .args(["-o", "link", "show", "dev", link])
        .output()
        .expect("`ip link show` runs");
    assert!(
        output.status.success(),
        "`ip link show {link}` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = String::from_utf8_lossy(&output.stdout);
    line.split("link/ether ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no MAC in `ip link show {link}`: {line}"))
        .to_owned()
}

/// Enters `namespace` on the current thread. Only that thread changes namespace, which is
/// what lets the test's main thread stay in the host namespace.
fn enter_namespace(namespace: &str) -> String {
    let path = format!("/run/netns/{namespace}");
    let file = std::fs::File::open(&path).expect("the test namespace mount is readable");
    // SAFETY: `file` is open for the duration of the call, and this thread is about to run
    // only the closure's socket code. `CLONE_NEWNET` changes this thread's network namespace,
    // not the process's.
    let result = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(
        result,
        0,
        "setns({path}) failed: {}",
        io::Error::last_os_error()
    );
    path
}

/// Sends one datagram from the client namespace and waits for one reply.
fn send_once(client_ns: &str, source: SocketAddr, destination: SocketAddr) -> io::Result<Vec<u8>> {
    let namespace = client_ns.to_owned();
    std::thread::spawn(move || {
        enter_namespace(&namespace);
        let socket = UdpSocket::bind(source)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.send_to(b"question", destination)?;
        let mut buffer = [0u8; 512];
        let (received, _) = socket.recv_from(&mut buffer)?;
        Ok(buffer[..received].to_vec())
    })
    .join()
    .expect("the client thread did not panic")
}

/// Sends one datagram from the client namespace without blocking a runtime worker.
///
/// The socket work runs on its own OS thread because `setns` is per-thread. The result comes
/// back through a Tokio channel so the daemon's runtime keeps polling its relay tasks while
/// the client waits for the reply.
async fn send_once_async(
    client_ns: &str,
    source: SocketAddr,
    destination: SocketAddr,
) -> io::Result<Vec<u8>> {
    let namespace = client_ns.to_owned();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(send_once(&namespace, source, destination));
    });
    receiver.await.expect("the client thread did not panic")
}

/// A UDP origin inside `origin_ns`, answering every datagram with `nonce`.
struct OriginGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for OriginGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn spawn_origin(origin_ns: &str, address: SocketAddr, nonce: String) -> OriginGuard {
    let namespace = origin_ns.to_owned();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        enter_namespace(&namespace);
        let socket = UdpSocket::bind(address).expect("the IPv6 UDP origin binds");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("the origin sets a read timeout");
        let mut buffer = [0u8; 512];
        while !thread_stop.load(Ordering::Acquire) {
            match socket.recv_from(&mut buffer) {
                Ok((_, peer)) => {
                    let _ = socket.send_to(nonce.as_bytes(), peer);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });
    OriginGuard {
        stop,
        thread: Some(thread),
    }
}

struct Fixture {
    client_ns: String,
    origin_ns: String,
    client_link: String,
    origin_link: String,
    client_host_link: String,
    origin_host_link: String,
    daemon_port: u16,
    forwarding_before: Option<String>,
    netns_dir_created: bool,
    cleaned: bool,
}

impl Fixture {
    fn new(daemon_port: u16) -> Option<Self> {
        let suffix = format!("{:x}", std::process::id() & 0xffff);
        let client_ns = format!("d6c{suffix}");
        let origin_ns = format!("d6o{suffix}");
        let client_link = format!("d6cc{suffix}");
        let origin_link = format!("d6oo{suffix}");
        let client_host_link = format!("d6hc{suffix}");
        let origin_host_link = format!("d6ho{suffix}");

        if Command::new("nft").arg("--version").output().is_err() {
            eprintln!("skipped: nft is not installed");
            return None;
        }
        if !std::path::Path::new("/proc/sys/net/ipv6").is_dir() {
            eprintln!("skipped: this kernel has no IPv6 stack");
            return None;
        }

        let netns_dir_created = !std::path::Path::new("/run/netns").is_dir();
        if netns_dir_created && std::fs::create_dir_all("/run/netns").is_err() {
            eprintln!("skipped: cannot create /run/netns (needs CAP_SYS_ADMIN)");
            return None;
        }

        let probe = format!("d6p{suffix}");
        if let Err(error) = run(&["ip", "netns", "add", &probe]) {
            let _ = run(&["ip", "netns", "del", &probe]);
            eprintln!("skipped: cannot create a network namespace: {error}");
            if netns_dir_created {
                let _ = std::fs::remove_dir("/run/netns");
            }
            return None;
        }
        let _ = run(&["ip", "netns", "del", &probe]);

        let forwarding_before =
            std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").ok();
        let mut fixture = Self {
            client_ns,
            origin_ns,
            client_link,
            origin_link,
            client_host_link,
            origin_host_link,
            daemon_port,
            forwarding_before,
            netns_dir_created,
            cleaned: false,
        };
        fixture.setup().expect("the IPv6 UDP fixture must set up");
        Some(fixture)
    }

    fn setup(&mut self) -> Result<(), String> {
        let client_cidr = format!("{CLIENT_IP}/64");
        let origin_cidr = format!("{ORIGIN_IP}/64");
        let client_host_cidr = format!("{CLIENT_HOST_IP}/64");
        let origin_host_cidr = format!("{ORIGIN_HOST_IP}/64");
        let client_gateway = CLIENT_HOST_IP.to_string();
        let origin_gateway = ORIGIN_HOST_IP.to_string();

        run(&["ip", "link", "set", "lo", "up"])?;
        run(&["ip", "netns", "add", &self.client_ns])?;
        run(&["ip", "netns", "add", &self.origin_ns])?;
        run(&[
            "ip",
            "link",
            "add",
            &self.client_host_link,
            "type",
            "veth",
            "peer",
            "name",
            &self.client_link,
        ])?;
        run(&[
            "ip",
            "link",
            "add",
            &self.origin_host_link,
            "type",
            "veth",
            "peer",
            "name",
            &self.origin_link,
        ])?;
        run(&[
            "ip",
            "link",
            "set",
            &self.client_link,
            "netns",
            &self.client_ns,
        ])?;
        run(&[
            "ip",
            "link",
            "set",
            &self.origin_link,
            "netns",
            &self.origin_ns,
        ])?;
        run(&["ip", "-n", &self.client_ns, "link", "set", "lo", "up"])?;
        run(&["ip", "-n", &self.origin_ns, "link", "set", "lo", "up"])?;
        run(&[
            "ip",
            "-n",
            &self.client_ns,
            "addr",
            "add",
            &client_cidr,
            "dev",
            &self.client_link,
            "nodad",
        ])?;
        run(&[
            "ip",
            "-n",
            &self.origin_ns,
            "addr",
            "add",
            &origin_cidr,
            "dev",
            &self.origin_link,
            "nodad",
        ])?;
        run(&[
            "ip",
            "-n",
            &self.client_ns,
            "link",
            "set",
            &self.client_link,
            "up",
        ])?;
        run(&[
            "ip",
            "-n",
            &self.origin_ns,
            "link",
            "set",
            &self.origin_link,
            "up",
        ])?;
        run(&["ip", "link", "set", &self.client_host_link, "up"])?;
        run(&["ip", "link", "set", &self.origin_host_link, "up"])?;
        run(&[
            "ip",
            "addr",
            "add",
            &client_host_cidr,
            "dev",
            &self.client_host_link,
            "nodad",
        ])?;
        run(&[
            "ip",
            "addr",
            "add",
            &origin_host_cidr,
            "dev",
            &self.origin_host_link,
            "nodad",
        ])?;
        run(&[
            "ip",
            "-n",
            &self.client_ns,
            "-6",
            "route",
            "add",
            "default",
            "via",
            &client_gateway,
            "dev",
            &self.client_link,
        ])?;
        run(&[
            "ip",
            "-n",
            &self.origin_ns,
            "-6",
            "route",
            "add",
            "default",
            "via",
            &origin_gateway,
            "dev",
            &self.origin_link,
        ])?;

        // Neighbor discovery depends on the link-local address, which can still be tentative
        // during DAD. Pin the four peer/gateway mappings so the test measures the proxy, not
        // a transient ND state.
        let client_mac = link_mac(Some(&self.client_ns), &self.client_link);
        let origin_mac = link_mac(Some(&self.origin_ns), &self.origin_link);
        let client_host_mac = link_mac(None, &self.client_host_link);
        let origin_host_mac = link_mac(None, &self.origin_host_link);
        run(&[
            "ip",
            "-6",
            "neigh",
            "replace",
            &CLIENT_IP.to_string(),
            "lladdr",
            &client_mac,
            "dev",
            &self.client_host_link,
            "nud",
            "permanent",
        ])?;
        run(&[
            "ip",
            "-6",
            "neigh",
            "replace",
            &ORIGIN_IP.to_string(),
            "lladdr",
            &origin_mac,
            "dev",
            &self.origin_host_link,
            "nud",
            "permanent",
        ])?;
        run(&[
            "ip",
            "-n",
            &self.client_ns,
            "-6",
            "neigh",
            "replace",
            &CLIENT_HOST_IP.to_string(),
            "lladdr",
            &client_host_mac,
            "dev",
            &self.client_link,
            "nud",
            "permanent",
        ])?;
        run(&[
            "ip",
            "-n",
            &self.origin_ns,
            "-6",
            "neigh",
            "replace",
            &ORIGIN_HOST_IP.to_string(),
            "lladdr",
            &origin_host_mac,
            "dev",
            &self.origin_link,
            "nud",
            "permanent",
        ])?;

        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
            .map_err(|error| format!("cannot enable IPv6 forwarding: {error}"))?;

        run(&[
            "ip",
            "-6",
            "rule",
            "del",
            "fwmark",
            TPROXY_MARK_SPEC,
            "table",
            POLICY_TABLE,
        ])
        .ok();
        run(&[
            "ip",
            "-6",
            "route",
            "del",
            "local",
            "default",
            "dev",
            "lo",
            "table",
            POLICY_TABLE,
        ])
        .ok();
        run(&[
            "ip",
            "-6",
            "rule",
            "add",
            "fwmark",
            TPROXY_MARK_SPEC,
            "table",
            POLICY_TABLE,
        ])?;
        run(&[
            "ip",
            "-6",
            "route",
            "add",
            "local",
            "default",
            "dev",
            "lo",
            "table",
            POLICY_TABLE,
        ])?;

        nft(&["add", "table", "ip6", "daer-udp6-test"])?;
        nft(&[
            "add",
            "chain",
            "ip6",
            "daer-udp6-test",
            "pre",
            "{",
            "type",
            "filter",
            "hook",
            "prerouting",
            "priority",
            "mangle",
            ";",
            "}",
        ])?;
        nft(&[
            "add",
            "rule",
            "ip6",
            "daer-udp6-test",
            "pre",
            "meta",
            "mark",
            "0x64616572",
            "return",
        ])?;
        let rule = format!(
            "iif {} ip6 daddr {} udp dport {} meta mark set {} tproxy to :{}",
            self.client_host_link, ORIGIN_IP, ORIGIN_PORT, TPROXY_MARK, self.daemon_port
        );
        let mut args = vec!["add", "rule", "ip6", "daer-udp6-test", "pre"];
        args.extend(rule.split(' '));
        nft(&args)?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        let _ = nft(&["delete", "table", "ip6", "daer-udp6-test"]);
        let _ = run(&[
            "ip",
            "-6",
            "rule",
            "del",
            "fwmark",
            TPROXY_MARK_SPEC,
            "table",
            POLICY_TABLE,
        ]);
        let _ = run(&[
            "ip",
            "-6",
            "route",
            "del",
            "local",
            "default",
            "dev",
            "lo",
            "table",
            POLICY_TABLE,
        ]);
        let _ = run(&["ip", "link", "del", &self.client_host_link]);
        let _ = run(&["ip", "link", "del", &self.origin_host_link]);
        let _ = run(&["ip", "netns", "del", &self.client_ns]);
        let _ = run(&["ip", "netns", "del", &self.origin_ns]);
        if let Some(previous) = &self.forwarding_before {
            let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", previous.trim());
        }
        if self.netns_dir_created {
            let _ = std::fs::remove_dir("/run/netns");
        }
    }
}

fn config() -> daer_config::Config {
    let text = r#"
schema = 6
wan-interface = ["lo"]
lan-interface = ["lo"]
disable-waiting-network = true
[routing]
default = "direct"
"#;
    daer_config::toml_config::load_str(text).expect("the IPv6 UDP configuration parses")
}

fn can_mark_sockets() -> bool {
    let Ok(socket) = UdpSocket::bind(("127.0.0.1", 0)) else {
        return false;
    };
    let mark: libc::c_uint = SOCKET_MARK;
    // SAFETY: `socket` is live for the call and `mark` is exactly the length passed.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_ref(&mark).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    result == 0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirected_ipv6_datagram_is_proxied_by_the_daemon() {
    let options = if can_mark_sockets() {
        RouterOptions::default().with_socket_mark(Some(SOCKET_MARK))
    } else {
        RouterOptions::default()
    };
    let Ok(daemon) = Daemon::bind(&config(), &options) else {
        eprintln!("skipped: cannot bind a transparent port without CAP_NET_ADMIN");
        return;
    };
    let port = daemon.port;
    let daemon = Arc::new(daemon);
    let Some(fixture) = Fixture::new(port) else {
        return;
    };

    let origin_address = SocketAddr::new(std::net::IpAddr::V6(ORIGIN_IP), ORIGIN_PORT);
    let nonce = format!(
        "{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos()
    );
    let origin = spawn_origin(&fixture.origin_ns, origin_address, nonce.clone());

    // Negative control: the tproxy rule is live but the daemon has not begun serving.
    // The client must not receive the origin's nonce; if it does, the redirect is not
    // intercepting this flow and the positive assertion below would be vacuous.
    let source = SocketAddr::new(std::net::IpAddr::V6(CLIENT_IP), 0);
    let before = send_once_async(&fixture.client_ns, source, origin_address).await;
    match before {
        Ok(reply) if reply == nonce.as_bytes() => {
            panic!("the negative control received the origin directly despite the tproxy rule")
        }
        Ok(_) | Err(_) => {}
    }
    let stats = daemon
        .datagram_stats()
        .expect("the daemon owns a datagram relay");
    let serve = tokio::spawn({
        let daemon = Arc::clone(&daemon);
        async move {
            daemon
                .serve(std::future::pending::<()>())
                .await
                .expect("the datagram relay must not stop the daemon");
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let reply = send_once_async(&fixture.client_ns, source, origin_address).await;
    let reply = match reply {
        Ok(reply) => reply,
        Err(error) => panic!(
            "the redirected IPv6 datagram must complete: {error}; relay stats: {:?}",
            stats.snapshot()
        ),
    };
    let body = String::from_utf8_lossy(&reply);
    assert!(
        body.contains(&nonce),
        "the origin's nonce must come back through the relay; got {body:?}"
    );
    assert!(
        stats.snapshot().to_client >= 1,
        "the relay must have written the reply back, got {:?}",
        stats.snapshot()
    );
    assert!(
        stats.snapshot().sessions_opened >= 1,
        "the relay must have opened a session, got {:?}",
        stats.snapshot()
    );

    drop(origin);
    serve.abort();
    let _ = serve.await;
    drop(daemon);
}
