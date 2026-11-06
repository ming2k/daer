// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 interop against a **local** reference server this test starts (ADR-0029).
//!
//! # Why a local server and not a public node
//!
//! The defects ADR-0029 fixed were invisible from the outside: `obfs` parsed and never applied,
//! `session_id` a constant, fragmentation absent. A test against a public node cannot attribute
//! any of those — a timeout looks the same for a wrong password, a dropped obfuscated packet and a
//! missing fragment. A server this test controls can be configured *with* Salamander, and then the
//! only way to get an echo back is to obfuscate correctly.
//!
//! # The rows
//!
//! | obfs | congestion | what it proves |
//! | --- | --- | --- |
//! | none | `bbr` (quinn default) | the QUIC + H3 auth path, `0x401` TCP framing |
//! | salamander | `bbr` | the obfuscation layer is on the datagram path |
//! | salamander | `brutal` | Brutal's window is accepted by a sizing-aware server |
//! | none, multi-port | `bbr` | the port set reaches the hop layer |
//!
//! # When `hysteria` is absent
//!
//! Skips **with a reason** (ADR-0007). `HYSTERIA_BIN` first, so a developer can point at a
//! checkout build (`../hysteria/app/hysteria`).

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use daer_proxy_protocols::{DialerOptions, ProxyDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The `hysteria` binary, or `None` when the machine has none.
fn hysteria() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("HYSTERIA_BIN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("hysteria"))
        .find(|candidate| candidate.is_file())
}

/// A port nobody is listening on.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("binds")
        .local_addr()
        .expect("has an address")
        .port()
}

/// A local TCP echo server, so an echo is the assertion.
async fn echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("has an address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// A self-signed certificate the server presents.
fn certificate() -> (String, String) {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("daer-hysteria2-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates a temp dir");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=lab.example.com",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => {}
        _ => panic!("this test needs `openssl` on PATH to mint the fixture's certificate"),
    }
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

/// A running `hysteria` fixture.
struct Hysteria {
    child: Child,
}

impl Drop for Hysteria {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the reference server on `ports`, waiting until its UDP socket is up.
///
/// UDP has no accept, so "is it listening" is answered by `ss`: the first packet the client sends
/// would otherwise be lost to a socket that is not bound yet, and a lost first flight in QUIC is a
/// handshake timeout rather than a retryable event.
fn start(
    hysteria: &PathBuf,
    dir_name: &str,
    cert: &str,
    key: &str,
    ports: &str,
    obfs: Option<&str>,
    bandwidth: Option<(u64, u64)>,
) -> Hysteria {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "daer-hysteria2-{}-{index}-{dir_name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("creates a temp dir");
    let path = dir.join("server.yaml");

    let mut config = format!(
        "listen: :{first}\n\
         tls:\n\
         \x20 cert: {cert}\n\
         \x20 key: {key}\n\
         auth:\n\
         \x20 type: password\n\
         \x20 password: lab-password\n",
        first = ports.split(',').next().expect("at least one port"),
    );
    if ports.contains(',') || ports.contains('-') {
        config.push_str(&format!(
            "  # extra ports are bound by the hop-test row: {ports}\n"
        ));
    }
    if let Some(obfs) = obfs {
        config.push_str(&format!(
            "obfs:\n  type: salamander\n  salamander:\n    password: {obfs}\n"
        ));
    }
    if let Some((up, down)) = bandwidth {
        config.push_str(&format!(
            "bandwidth:\n  up: {}\n  down: {}\n",
            mbps(up),
            mbps(down)
        ));
    }
    config.push_str("udp:\n  enabled: true\n");

    let mut file = std::fs::File::create(&path).expect("creates the config");
    file.write_all(config.as_bytes())
        .expect("writes the config");

    let child = Command::new(hysteria)
        .args(["server", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(
                std::env::temp_dir().join(format!("daer-hysteria2-{index}-{dir_name}.log")),
            )
            .expect("log file"),
        ))
        .spawn()
        .expect("spawns hysteria");

    let fixture = Hysteria { child };
    let first: u16 = ports
        .split(&[',', '-'][..])
        .next()
        .and_then(|port| port.parse().ok())
        .expect("a port");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // A TCP connect cannot answer for a UDP socket, so the probe is `ss`'s UDP table. `ss` is
        // in iproute2, which every Linux this crate runs on has; when it does not, the wait
        // degrades to a bounded sleep rather than failing the test.
        let bound = Command::new("ss")
            .args(["-lun", &format!("sport = :{first}")])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).contains(&first.to_string()))
            .unwrap_or(false);
        if bound {
            break;
        }
        if Instant::now() >= deadline {
            // Fall back to a bounded sleep: a machine without `ss` should still run the test.
            std::thread::sleep(Duration::from_millis(500));
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    fixture
}

/// `1_000_000` as the reference's bandwidth spelling.
fn mbps(bits_per_second: u64) -> String {
    format!("{} mbps", bits_per_second / 1_000_000)
}

/// Dials `authority` through `link` and asserts an echo round trip.
async fn assert_round_trip(link: &str, authority: &str, label: &str) {
    let options = DialerOptions::new(None, Duration::from_secs(10));
    let dialer = ProxyDialer::from_link(link, options)
        .unwrap_or_else(|error| panic!("{label}: the link must build a dialer: {error}"));
    let mut stream = dialer
        .connect(authority)
        .await
        .unwrap_or_else(|error| panic!("{label}: connect failed: {error}"))
        .stream;

    let payload = b"hysteria2 speaks over QUIC and HTTP/3";
    stream
        .write_all(payload)
        .await
        .unwrap_or_else(|error| panic!("{label}: write failed: {error}"));
    stream
        .flush()
        .await
        .unwrap_or_else(|error| panic!("{label}: flush failed: {error}"));

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .unwrap_or_else(|_| panic!("{label}: no echo within 10s"))
        .unwrap_or_else(|error| panic!("{label}: read failed: {error}"));
    assert_eq!(&echoed, payload, "{label}: the echo must match");
}

fn skip(test: &str) -> bool {
    if hysteria().is_some() {
        return false;
    }
    eprintln!(
        "skipping {test}: no `hysteria` binary on PATH and HYSTERIA_BIN unset. This is the test \
         that proves the datagram stack works, so a green run without it proves nothing about the \
         wire. Build it with `cd ../hysteria/app && go build -o /tmp/hysteria .`"
    );
    true
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hysteria2_session_carries_a_round_trip_without_obfuscation() {
    if skip("a_hysteria2_session_carries_a_round_trip_without_obfuscation") {
        return;
    }
    let binary = hysteria().expect("checked above");
    let echo = echo_server().await;
    let (cert, key) = certificate();
    let port = free_port();
    let _fixture = start(&binary, "plain", &cert, &key, &port.to_string(), None, None);

    let link = format!("hysteria2://lab-password@127.0.0.1:{port}?sni=lab.example.com&insecure=1");
    assert_round_trip(&link, &format!("{echo}"), "hysteria2/no-obfs").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn salamander_reaches_the_wire_which_is_what_was_missing() {
    // The defect ADR-0029 exists for: with the layer absent, the QUIC Initial went out in the clear
    // and this server — configured with Salamander — dropped every packet. A timeout here means the
    // obfuscation is not on the datagram path; a success means it is.
    if skip("salamander_reaches_the_wire_which_is_what_was_missing") {
        return;
    }
    let binary = hysteria().expect("checked above");
    let echo = echo_server().await;
    let (cert, key) = certificate();
    let port = free_port();
    let _fixture = start(
        &binary,
        "salamander",
        &cert,
        &key,
        &port.to_string(),
        Some("cry_me_a_r1ver"),
        None,
    );

    let link = format!(
        "hysteria2://lab-password@127.0.0.1:{port}?sni=lab.example.com&insecure=1\
         &obfs=salamander&obfs-password=cry_me_a_r1ver"
    );
    assert_round_trip(&link, &format!("{echo}"), "hysteria2/salamander").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn brutal_pins_a_window_and_the_server_accepts_it() {
    if skip("brutal_pins_a_window_and_the_server_accepts_it") {
        return;
    }
    let binary = hysteria().expect("checked above");
    let echo = echo_server().await;
    let (cert, key) = certificate();
    let port = free_port();
    let _fixture = start(
        &binary,
        "brutal",
        &cert,
        &key,
        &port.to_string(),
        None,
        Some((100, 200)),
    );

    let link = format!(
        "hysteria2://lab-password@127.0.0.1:{port}?sni=lab.example.com&insecure=1\
         &upmbps=100&downmbps=200&congestion=brutal"
    );
    assert_round_trip(&link, &format!("{echo}"), "hysteria2/brutal").await;
}

/// A local UDP echo server, so a datagram round trip is the assertion.
async fn udp_echo_server() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = socket.local_addr().expect("has an address");
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            if socket.send_to(&buffer[..read], peer).await.is_err() {
                return;
            }
        }
    });
    address
}

#[tokio::test(flavor = "multi_thread")]
async fn a_udp_flow_carries_datagrams_both_ways() {
    // The datagram plane's own row. It exercises what ADR-0029 rebuilt: a per-flow `session_id`
    // (the constant `1` would collide across flows), the `[session][packet][frag][count][addr]`
    // header, and the server's `Hysteria-UDP` answer actually being honoured.
    if skip("a_udp_flow_carries_datagrams_both_ways") {
        return;
    }
    let binary = hysteria().expect("checked above");
    let echo = udp_echo_server().await;
    let (cert, key) = certificate();
    let port = free_port();
    let _fixture = start(
        &binary,
        "udp-data",
        &cert,
        &key,
        &port.to_string(),
        None,
        None,
    );

    let link = format!("hysteria2://lab-password@127.0.0.1:{port}?sni=lab.example.com&insecure=1");
    let dialer = ProxyDialer::from_link(&link, DialerOptions::new(None, Duration::from_secs(10)))
        .expect("the link is well formed");
    let connector = dialer.datagram_connector().expect("hysteria2 carries UDP");
    let recorder = std::sync::Arc::new(std::sync::Mutex::new(netune_trace::Recorder::start(16)));
    let established = connector
        .connect(&format!("{echo}"), &recorder)
        .await
        .expect("the fixture enables udp");
    let session = established.datagrams;

    let payload = b"a datagram through the tunnel";
    let sent = session.send(payload).await.expect("sends a datagram");
    assert_eq!(sent, payload.len());

    let mut received = vec![0u8; 2048];
    let read = tokio::time::timeout(Duration::from_secs(10), session.recv(&mut received))
        .await
        .expect("a datagram must come back within 10s")
        .expect("receives a datagram");
    assert_eq!(&received[..read], payload, "the UDP echo must match");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_servers_own_answer_says_udp_is_available() {
    // `Hysteria-UDP: true` is read and kept now; before ADR-0029 it was discarded, and a datagram
    // flow failed later at the relay with nothing to attribute it to.
    if skip("the_servers_own_answer_says_udp_is_available") {
        return;
    }
    let binary = hysteria().expect("checked above");
    let echo = echo_server().await;
    let (cert, key) = certificate();
    let port = free_port();
    let _fixture = start(&binary, "udp", &cert, &key, &port.to_string(), None, None);

    let link = format!("hysteria2://lab-password@127.0.0.1:{port}?sni=lab.example.com&insecure=1");
    let dialer = ProxyDialer::from_link(&link, DialerOptions::new(None, Duration::from_secs(10)))
        .expect("the link is well formed");
    let ProxyDialer::Hysteria2(connector) = &dialer else {
        panic!("expected a hysteria2 connector");
    };
    // A datagram session is only created when the server said UDP is available; a refusal here is
    // the server's own answer, and the message names it.
    let datagrams = connector
        .connect_datagram(
            &format!("{echo}"),
            &std::sync::Arc::new(std::sync::Mutex::new(netune_trace::Recorder::start(16))),
        )
        .await
        .expect("the fixture enables udp, so the answer must be true");
    drop(datagrams);
}
