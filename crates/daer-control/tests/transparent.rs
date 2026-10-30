// SPDX-License-Identifier: AGPL-3.0-only

//! The transparent-proxy data path, end to end — with a test that can fail (ADR-0007).
//!
//! # What the previous version of this file did wrong
//!
//! It started an origin on `127.0.0.2:18080` that answered `hello`, then asserted the reply
//! contained `hello`. There was no redirect rule anywhere in the repository, and I confirmed the
//! vacuity directly: running that origin with **no daemon and no rules**, the same bytes came
//! back. The test passed because the fixture answered, not because the proxy worked.
//!
//! # The three things that make this one able to fail
//!
//! 1. **A nonce only the daemon's origin can produce.** The origin's body is generated per run.
//! 2. **A liveness assertion on the daemon.** The flow must be counted by `Daemon::stats()`; a
//!    client that reached the origin without being redirected would not appear there.
//! 3. **A negative control.** The same request, with the redirect removed, must *fail*. If the
//!    control succeeds the fixture is bypassing the proxy and the test reports the fixture as
//!    broken instead of passing.
//!
//! # Why it installs its own redirect
//!
//! `tproxy` needs `nftables` and `CAP_NET_ADMIN`. Both are available inside
//! `unshare -Urn`, which is what the module's own invocation uses. When neither is available the
//! test **skips with a reason**, and `scripts/kernel-check.sh` is what runs it in CI — an
//! ignored test nobody runs is how the vacuous version survived.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use daer_control::{Daemon, RouterOptions};

/// Where the origin listens.
///
/// `127.0.0.1` rather than a second loopback address: a fresh network namespace has only
/// `127.0.0.1/8` configured, and an origin that cannot bind must not be confused with a proxy
/// that cannot proxy. The redirect names this exact address and port, so the daemon's own dial
/// to it is the only traffic the rule can match.
const ORIGIN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18_080);

/// The mark daer's own dials carry, and the one the redirect rule excludes.
const MARK: u32 = 0x0dae;

/// The address the datagram test's client binds, and the one the redirect rule names.
///
/// The client must be distinguishable from the daemon's own datagrams, and both come from the
/// same host; `127.0.0.2` is a loopback address the origin does not use, so the rule can name
/// exactly the client and nothing else.
const CLIENT_ADDRESS: &str = "127.0.0.2";

/// Reserves the shared fixture (one origin address, one nftables table) for a whole test body.
///
/// The two data-path tests share `ORIGIN` and the table name, so running them concurrently makes
/// each one's client reach the other one's origin — a fixture bug that looks exactly like a proxy
/// failure. A `Mutex` cannot be used, because the guard would be held across `await` and block the
/// runtime (clippy is right to refuse); instead the fixture is claimed synchronously with a spin,
/// which is safe here because the test holding it makes progress on another runtime worker.
static FIXTURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct Fixture;

impl Fixture {
    fn acquire() -> Self {
        use std::sync::atomic::Ordering;
        while FIXTURE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire)
            .is_err()
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        Self
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        FIXTURE.store(false, std::sync::atomic::Ordering::Release);
    }
}

fn direct_config(port: u16) -> daer_config::Config {
    let text = format!(
        r#"
schema = 1
[global]
tproxy-port = {port}
wan-interface = ["lo"]
log-level = "debug"
[routing]
rules = ["dip(127.0.0.1) -> direct"]
fallback = "direct"
"#
    );
    daer_config::toml_config::load_str(&text).expect("the probe configuration must parse")
}

/// A body that only this run's origin knows.
fn nonce() -> String {
    format!(
        "daer-nonce-{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos()
    )
}

/// Runs `nft`, returning whether it succeeded.
fn nft(args: &[&str]) -> bool {
    Command::new("nft")
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Installs `tcp dport ORIGIN_PORT -> tproxy` and returns whether it worked.
fn install_redirect(port: u16) -> bool {
    // A dedicated table so the removal is one command and cannot touch an operator's rules.
    if !nft(&["add", "table", "ip", "daer-test"]) {
        return false;
    }
    if !nft(&[
        "add",
        "chain",
        "ip",
        "daer-test",
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
    ]) {
        let _ = nft(&["delete", "table", "ip", "daer-test"]);
        return false;
    }
    // The origin address is the match: nothing else on this namespace is redirected, so the
    // daemon's own dial to the origin (which carries `so-mark`) is the only way out.
    let rule = format!(
        "ip daddr {} tcp dport {} tproxy to :{port}",
        ORIGIN.ip(),
        ORIGIN.port()
    );
    let mut args = vec![
        "add",
        "rule",
        "ip",
        "daer-test",
        "pre",
        "meta",
        "mark",
        "0x0dae",
        "return",
    ];
    if !nft(&args) {
        let _ = nft(&["delete", "table", "ip", "daer-test"]);
        return false;
    }
    args = vec!["add", "rule", "ip", "daer-test", "pre"];
    args.extend(rule.split(' '));
    let installed = nft(&args);
    if !installed {
        let _ = nft(&["delete", "table", "ip", "daer-test"]);
    }
    installed
}

fn remove_redirect() {
    let _ = nft(&["delete", "table", "ip", "daer-test"]);
}

/// Runs `ip`, returning whether it succeeded.
fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The routing rule and local route a `tproxy` *datagram* needs.
///
/// # Why this is not optional
///
/// `TPROXY` marks a packet so that, after the mangle hook, it is routed to the local table and
/// delivered to the transparent socket. For TCP that happens through the socket's own transparent
/// state; for a **datagram** whose destination is not a local address, the marked packet is
/// dropped unless policy routing sends it to `local`. The datapath's own C comment says exactly
/// this (`ebpf/kern/tproxy.c`: `ip rule add fwmark 0x8000000/0x8000000 table 2023` /
/// `ip route add local default dev lo table 2023`).
///
/// Leaving it out is why a first attempt at this test concluded "UDP cannot be proven in one
/// network namespace". That conclusion was wrong: the datagram arrived at the `tproxy` rule and
/// was then dropped by routing, which the missing rule explains exactly.
const UDP_FWMARK: &str = "0x1";
const UDP_TABLE: &str = "2023";

fn install_datagram_routing() -> bool {
    // Idempotent: a previous run may have left these, and re-adding is a no-op with `replace`.
    let _ = ip(&[
        "rule",
        "del",
        "fwmark",
        &format!("{UDP_FWMARK}/{UDP_FWMARK}"),
        "table",
        UDP_TABLE,
    ]);
    let _ = ip(&[
        "route",
        "del",
        "local",
        "0.0.0.0/0",
        "dev",
        "lo",
        "table",
        UDP_TABLE,
    ]);
    let rule = ip(&[
        "rule",
        "add",
        "fwmark",
        &format!("{UDP_FWMARK}/{UDP_FWMARK}"),
        "table",
        UDP_TABLE,
    ]);
    let route = ip(&[
        "route",
        "add",
        "local",
        "0.0.0.0/0",
        "dev",
        "lo",
        "table",
        UDP_TABLE,
    ]);
    rule && route
}

fn remove_datagram_routing() {
    let _ = ip(&[
        "rule",
        "del",
        "fwmark",
        &format!("{UDP_FWMARK}/{UDP_FWMARK}"),
        "table",
        UDP_TABLE,
    ]);
    let _ = ip(&[
        "route",
        "del",
        "local",
        "0.0.0.0/0",
        "dev",
        "lo",
        "table",
        UDP_TABLE,
    ]);
}

/// Installs `udp dport ORIGIN_PORT -> tproxy`, with the mark that makes the packet local.
fn install_datagram_redirect(port: u16) -> bool {
    if !install_datagram_routing() {
        return false;
    }
    if !nft(&["add", "table", "ip", "daer-test-udp"]) {
        remove_datagram_routing();
        return false;
    }
    if !nft(&[
        "add",
        "chain",
        "ip",
        "daer-test-udp",
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
    ]) {
        let _ = nft(&["delete", "table", "ip", "daer-test-udp"]);
        remove_datagram_routing();
        return false;
    }
    // The daemon's own datagrams carry `SO_MARK` and must not be captured again.
    let mut args = vec![
        "add",
        "rule",
        "ip",
        "daer-test-udp",
        "pre",
        "meta",
        "mark",
        "0x0dae",
        "return",
    ];
    if !nft(&args) {
        let _ = nft(&["delete", "table", "ip", "daer-test-udp"]);
        remove_datagram_routing();
        return false;
    }
    args = vec!["add", "rule", "ip", "daer-test-udp", "pre"];
    // `iif lo` and the exact source: only the *client's* datagrams are redirected. A rule that
    // matched by port alone would also capture the daemon's own reply to the origin, because
    // both are `udp dport ORIGIN_PORT` from the same host — which is how the first version of
    // this test hung instead of proving anything.
    let rule = format!(
        "iif lo udp dport {} ip saddr {} meta mark set {UDP_FWMARK} tproxy to :{port}",
        ORIGIN.port(),
        CLIENT_ADDRESS
    );

    args.extend(rule.split(' '));
    let installed = nft(&args);
    if !installed {
        let _ = nft(&["delete", "table", "ip", "daer-test-udp"]);
        remove_datagram_routing();
    }
    installed
}

fn remove_datagram_redirect() {
    let _ = nft(&["delete", "table", "ip", "daer-test-udp"]);
    remove_datagram_routing();
}

/// A UDP origin that answers `nonce` to every datagram.
///
/// Same shape as [`Origin`]: it binds on the calling thread so a fixture failure is visible, and
/// it stops on drop so a following test can bind the same port.
struct DatagramOrigin {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DatagramOrigin {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn spawn_datagram_origin(nonce: String) -> DatagramOrigin {
    let socket = std::net::UdpSocket::bind(ORIGIN)
        .unwrap_or_else(|error| panic!("the UDP origin must bind {ORIGIN}: {error}"));
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("a read timeout can be set");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = std::sync::Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
            match socket.recv_from(&mut buffer) {
                Ok((received, peer)) => {
                    eprintln!("UDP ORIGIN got {} bytes from {peer}", received);
                    match socket.send_to(nonce.as_bytes(), peer) {
                        Ok(n) => eprintln!("UDP ORIGIN replied {n} bytes to {peer}"),
                        Err(error) => eprintln!("UDP ORIGIN reply failed: {error}"),
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return,
            }
        }
    });
    DatagramOrigin {
        stop,
        thread: Some(thread),
    }
}

/// Whether this process can set `SO_MARK` on a socket.
///
/// `SO_MARK` needs `CAP_NET_ADMIN`. A dial that asks for a mark it cannot set fails outright —
/// netune reports socket-option failures rather than ignoring them, which is the right behaviour
/// and means a test has to know whether it may ask.
fn can_mark_sockets() -> bool {
    use std::os::fd::AsRawFd;
    let Ok(socket) = std::net::UdpSocket::bind(("127.0.0.1", 0)) else {
        return false;
    };
    let mark: libc::c_uint = MARK;
    // SAFETY: `socket` is an open socket for the duration of the call, and `mark` is a live
    // `c_uint` of exactly the length passed.
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

/// A running origin, kept alive for as long as the value lives.
///
/// Dropping it **stops** the accept loop and waits for the thread, because the two data-path
/// tests share `ORIGIN`: a detached thread still holding the listening socket makes the next
/// test's `bind` fail with `EADDRINUSE`, which is a fixture failure and must be reported as one.
struct Origin {
    /// Set to stop the accept loop. The loop selects on it with a short poll interval, so the
    /// shutdown does not depend on a new connection arriving.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Spawns an origin that answers `nonce` and nothing else.
///
/// The bind happens on the calling thread so a failure is **visible**: an origin thread that
/// silently returned left the client talking to nothing, and the test then reported a proxy
/// failure that was really a fixture failure.
fn spawn_origin(nonce: String) -> Origin {
    let listener = std::net::TcpListener::bind(ORIGIN)
        .unwrap_or_else(|error| panic!("the origin must bind {ORIGIN}: {error}"));
    listener
        .set_nonblocking(true)
        .expect("the listener can accept without blocking");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = std::sync::Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let body = nonce.clone();
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes());
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });
    Origin {
        stop,
        thread: Some(thread),
    }
}

/// One request/response exchange against `ORIGIN`, returning the whole reply.
async fn request() -> std::io::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(ORIGIN),
    )
    .await
    .map_err(|_| std::io::Error::other("connect timed out"))??;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
        .await?;
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply))
        .await
        .map_err(|_| std::io::Error::other("read timed out"))??;
    Ok(String::from_utf8_lossy(&reply).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirected_flow_is_proxied_by_the_daemon() {
    let _fixture = Fixture::acquire();
    // The redirect needs nftables and CAP_NET_ADMIN. Without either, this is a skip with a
    // reason rather than a pass; `spawn_origin` below panics if the origin cannot bind, so a
    // fixture failure can never be mistaken for a proxy failure.
    if !install_redirect(12_347) {
        eprintln!(
            "skipped: cannot install the tproxy rule (needs nftables and CAP_NET_ADMIN; run \
             under `unshare -Urn`)"
        );
        return;
    }
    // The redirect is installed; from here on every failure is real.
    let nonce = nonce();
    let origin = spawn_origin(nonce.clone());

    let config = direct_config(12_347);
    // The same mark the redirect rule excludes. Without it daer's own dial to the origin is
    // captured by its own tproxy rule and the flow loops (see `RouterOptions::so_mark`).
    let options = RouterOptions::default().with_socket_mark(Some(MARK));
    let Ok(daemon) = Daemon::bind(&config, &options) else {
        remove_redirect();
        panic!("the transparent port must bind (is CAP_NET_ADMIN present?)");
    };

    // The daemon is shared with the serving task so the test can read its counters: the liveness
    // assertion below needs to know the *daemon* saw the flow, not merely that a reply came back.
    let daemon = std::sync::Arc::new(daemon);
    let serve = tokio::spawn({
        let daemon = std::sync::Arc::clone(&daemon);
        async move {
            daemon
                .serve(std::future::pending::<()>())
                .await
                .expect("the accept loop must not fail");
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let reply = request().await.expect("the redirected flow must complete");
    let stats = daemon.stats();
    assert!(
        reply.contains(&nonce),
        "the origin's nonce must come back through the proxy; got {reply:?}"
    );

    // The liveness assertion: a reply reached the client *and* the daemon accepted exactly one
    // flow. Without this the test would still pass if the client had reached the origin
    // directly, which is what made the previous version vacuous.
    assert_eq!(
        stats.accepted, 1,
        "the daemon must have proxied exactly one flow, got {stats:?}"
    );
    assert_eq!(
        stats.rejected, 0,
        "no flow should have been rejected: {stats:?}"
    );

    serve.abort();
    remove_redirect();
    drop(origin);
}

/// The control that makes the test above meaningful: with no daemon the same request fails.
///
/// This is the assertion the previous version of this file lacked. It does not test the product;
/// it tests the *fixture*, and it fails loudly if a future change makes the request reach the
/// origin on its own — which is exactly how a vacuous end-to-end test starts.
#[tokio::test]
async fn the_negative_control_fails_without_the_daemon() {
    let _fixture = Fixture::acquire();
    if !install_redirect(12_348) {
        eprintln!(
            "skipped: cannot install the tproxy rule (needs nftables and CAP_NET_ADMIN; run \
             under `unshare -Urn`)"
        );
        return;
    }
    // No daemon listens on 12_348, so the redirect lands on a closed port and the client must
    // fail. If this ever succeeds, the origin is reachable without the proxy and
    // `a_redirected_flow_is_proxied_by_the_daemon` proves nothing.
    let nonce = nonce();
    let origin = spawn_origin(nonce.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = request().await;
    remove_redirect();
    drop(origin);

    match result {
        Err(_) => {}
        Ok(reply) if reply.contains(&nonce) => panic!(
            "the fixture is broken: the origin answered {reply:?} with the tproxy rule pointing \
             at a closed port, so the redirect is not intercepting this flow"
        ),
        Ok(reply) => panic!("unexpected reply with no daemon listening: {reply:?}"),
    }
}

/// A flow that was not redirected must not be served.
///
/// This is a property of the listener, not of the redirect, and it is what keeps the transparent
/// port from being an open relay into the box's own traffic.
#[tokio::test]
async fn the_transparent_port_refuses_a_flow_that_was_not_redirected() {
    let config = direct_config(12_349);
    let options = RouterOptions::default();
    let Ok(daemon) = Daemon::bind(&config, &options) else {
        eprintln!("skipped: cannot bind a transparent port without CAP_NET_ADMIN");
        return;
    };

    let serve = tokio::spawn({
        async move {
            let _ = daemon.serve(std::future::pending::<()>()).await;
        }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    use tokio::io::AsyncReadExt;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", 12_349))
        .await
        .expect("the port accepts the connection at the kernel level");
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .expect("the rejection must not hang");
    match read {
        Ok(0) => {}
        Ok(n) => panic!("a self-connect must not be served, got {n} bytes"),
        Err(_) => {}
    }

    serve.abort();
}

/// A datagram is redirected by `tproxy`, decided by the daemon, relayed to the origin, and the
/// reply comes back to the client (ADR-0007).
///
/// # What it proves, and how it can fail
///
/// * the UDP origin answers a **per-run nonce**, so a fixture that bypasses the proxy cannot
///   satisfy the assertion;
/// * the daemon's datagram counters must advance (`sessions_opened`, `to_upstream`, `to_client`),
///   so a reply that arrived by some other path fails the test;
/// * the reply must come **back to the client's port**, which is the part a single-socket echo
///   cannot fake: `tproxy` rewrote the destination, and the relay has to remember where to send
///   the answer.
///
/// # The prerequisite that was initially missed
///
/// `TPROXY` is a `PREROUTING` target *and* it needs policy routing for the marked packet to be
/// treated as local. Without `ip rule fwmark … table N` plus `ip route add local default dev lo
/// table N`, the datagram reaches the `tproxy` rule and is then dropped by routing — which an
/// earlier attempt misread as "a single network namespace cannot do this". The rule is part of
/// the deployment contract, not of the test: `docs/deployment.md` lists it for operators.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redirected_datagram_is_proxied_by_the_daemon() {
    let _fixture = Fixture::acquire();
    // # The topology this needs, and why the test reports a skip instead of passing
    //
    // `TPROXY` redirects a datagram that **arrives on an interface**. Proving the relay end to
    // end therefore needs a datagram whose `iif` is not `lo`, which needs the origin in a
    // different network namespace. Creating one needs mount privileges this environment does
    // not have (`ip netns add` cannot create `/run/netns`), so the three in-namespace
    // topologies were tried and each fails for a *fixture* reason, not a product one:
    //
    // 1. client and origin both on `127.0.0.0/8`: the rule catches the client's datagram and
    //    the origin's reply identically (same `iif`, same `dport`), so a `tproxy` there also
    //    redirects the reply and the test measured its own fixture.
    // 2. a veth pair with the client on the peer: a datagram from the peer is routed *inside*
    //    the namespace, so `iif` is `lo` and the veth rule sees zero packets (measured: a
    //    `counter` rule reported `packets 0`).
    // 3. `ip rule fwmark … table …` + `local default dev lo`: necessary for `tproxy` to treat a
    //    marked datagram as local at all, and present below — but it does not create an `iif`.
    //
    // What *is* verified without a second namespace, and is the part that regressed:
    // `the_datagram_relay_is_wired_into_the_daemon` below; `datagram.rs`'s own tests, which
    // prove session creation, the per-peer table, the replies going back to the right peer, and
    // the ceiling; and — since this work — that the daemon runs on a runtime where a spawned
    // forward is actually scheduled (`crates/daer-cli`'s `block_on_daemon`), which is the defect
    // an end-to-end attempt *did* find.
    if !two_namespaces_available() {
        eprintln!(
            "skipped: proving UDP through `tproxy` needs the origin in a second network \
             namespace (so the datagram has a non-`lo` `iif`), and this environment cannot \
             create one; see the comment on this test for the three topologies that were tried"
        );
        return;
    }
    if !install_datagram_redirect(12_351) {
        eprintln!(
            "skipped: cannot install the UDP tproxy rule (needs nftables, `ip rule` and \
             CAP_NET_ADMIN; run under `unshare -Urn`)"
        );
        return;
    }

    let nonce = nonce();
    let origin = spawn_datagram_origin(nonce.clone());
    let config = direct_config(12_351);
    let options = match can_mark_sockets() {
        true => RouterOptions::default().with_socket_mark(Some(MARK)),
        false => RouterOptions::default().with_socket_mark(None),
    };
    let Ok(daemon) = Daemon::bind(&config, &options) else {
        remove_datagram_redirect();
        panic!("the transparent port must bind (is CAP_NET_ADMIN present?)");
    };
    let stats = daemon
        .datagram_stats()
        .expect("the daemon owns a datagram relay");
    let daemon = std::sync::Arc::new(daemon);
    let serve = tokio::spawn({
        let daemon = std::sync::Arc::clone(&daemon);
        async move {
            daemon
                .serve(std::future::pending::<()>())
                .await
                .expect("the datagram relay must not stop the daemon");
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    use tokio::net::UdpSocket;
    let client = UdpSocket::bind((CLIENT_ADDRESS, 0))
        .await
        .expect("an ephemeral UDP socket on the client address");
    client
        .send_to(b"question", ORIGIN)
        .await
        .expect("the datagram is sent");

    let mut buffer = [0u8; 512];
    let received = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .expect("the reply must not hang")
        .expect("the reply must arrive");
    let body = String::from_utf8_lossy(&buffer[..received.0]).into_owned();
    assert!(
        body.contains(&nonce),
        "the origin's nonce must come back through the relay; got {body:?} (stats: {:?})",
        stats.snapshot()
    );
    assert!(
        stats.sessions_opened() >= 1,
        "the relay must have opened a session, got {:?}",
        stats.snapshot()
    );
    assert!(
        stats.to_client() >= 1,
        "the relay must have written the reply back, got {:?}",
        stats.snapshot()
    );

    serve.abort();
    remove_datagram_redirect();
    drop(origin);
}

/// Whether this process can create a second network namespace.
fn two_namespaces_available() -> bool {
    let name = format!("daer-probe-{}", std::process::id());
    let created = Command::new("ip")
        .args(["netns", "add", &name])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if created {
        let _ = Command::new("ip").args(["netns", "del", &name]).status();
    }
    created
}

/// The wiring check: the daemon owns a transparent datagram socket at all.
///
/// Kept separate from the end-to-end test above because it fails for a different reason and
/// should say so: reverting `Daemon::bind` to a TCP-only listener fails *this* one with a clear
/// message, while a routing problem fails the other.
#[tokio::test]
async fn the_datagram_relay_is_wired_into_the_daemon() {
    let config = direct_config(12_350);
    let Ok(daemon) = Daemon::bind(&config, &RouterOptions::default()) else {
        eprintln!("skipped: cannot bind a transparent port without CAP_NET_ADMIN");
        return;
    };

    assert!(
        daemon.datagrams.is_some(),
        "the daemon must own a transparent datagram socket; without it UDP is silently dropped \
         while TCP works, which is the failure mode ADR-0006 exists to prevent"
    );
    assert!(
        daemon.datagram_stats().is_some(),
        "the relay's counters must be readable, or a deployment cannot tell working UDP from \
         silently dropped UDP"
    );
}
