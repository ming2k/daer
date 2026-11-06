// SPDX-License-Identifier: AGPL-3.0-only

//! VMess AEAD against a **local** `xray` inbound (ADR-0030).
//!
//! # What this proves that a unit test cannot
//!
//! The KDF, the `AuthID`, the sealed header and the chunk stream are each pinned to the
//! reference's own bytes in `vmess::`'s unit tests. What none of those can show is that Xray
//! *accepts* the combination — that the header's field order is what its parser reads, that the
//! option bits mean what its writer means, and that the two data planes (stream and packet) line
//! up with `TransferType`.
//!
//! So this starts a real `xray` VMess inbound per row and asserts a round trip:
//!
//! | cipher | `AuthenticatedLength` | transport |
//! | --- | --- | --- |
//! | `auto` | off | tcp |
//! | `aes-128-gcm` | off | tcp |
//! | `chacha20-poly1305` | off | tcp |
//! | `auto` | **on** | tcp |
//! | `auto` | off | **ws** |
//!
//! `AuthenticatedLength` has its own row because it changes the size field's wire format, and a
//! client that always enables it cannot talk to a default server — which is why ADR-0030 makes it
//! explicit rather than defaulted.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use daer_proxy_protocols::{DialerOptions, ProxyDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "df4af3d0-030e-4062-baa6-eb9dd45298ef";

fn xray() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XRAY_BIN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("xray"))
        .find(|candidate| candidate.is_file())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("binds")
        .local_addr()
        .expect("has an address")
        .port()
}

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

struct Xray {
    child: Child,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts an `xray` fixture with one VMess inbound.
///
/// `extra_settings` goes into the user object (`"testseed"` and friends would, but the two flags
/// this crate cares about are `AuthenticatedLength`/`NoTerminationSignal`, which Xray reads from
/// `testsEnabled`).
fn start(xray: &PathBuf, label: &str, network: &str, tests_enabled: &str) -> (Xray, u16, PathBuf) {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("daer-vmess-{}-{index}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates a temp dir");
    let path = dir.join("config.json");
    let port = free_port();

    let transport = if network == "ws" {
        r#", "wsSettings": { "path": "/vm" }"#
    } else {
        ""
    };
    let tests = if tests_enabled.is_empty() {
        String::new()
    } else {
        format!(r#", "testsEnabled": "{tests_enabled}""#)
    };
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "vmess",
      "listen": "127.0.0.1",
      "port": {port},
      "protocol": "vmess",
      "settings": {{
        "clients": [{{ "id": "{UUID}", "level": 0{tests} }}]
      }},
      "streamSettings": {{ "network": "{network}", "security": "none"{transport} }}
    }}
  ],
  "outbounds": [
    {{ "tag": "freedom", "protocol": "freedom", "settings": {{ "finalRules": [{{ "action": "allow" }}] }} }}
  ]
}}"#
    );

    let mut file = std::fs::File::create(&path).expect("creates the config");
    file.write_all(config.as_bytes())
        .expect("writes the config");

    let child = Command::new(xray)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::from({
            let log = std::env::temp_dir().join(format!(
                "daer-vmess-{}-{index}-{label}.log",
                std::process::id()
            ));
            std::fs::File::create(&log).expect("log file")
        }))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawns xray");

    let fixture = Xray { child };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "xray never listened on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = std::env::temp_dir().join(format!(
        "daer-vmess-{}-{index}-{label}.log",
        std::process::id()
    ));
    (fixture, port, log)
}

/// Dials `authority` through `link` and asserts an echo round trip.
async fn assert_round_trip(link: &str, authority: &str, label: &str, log: &std::path::Path) {
    let options = DialerOptions::new(None, Duration::from_secs(10));
    let dialer = ProxyDialer::from_link(link, options)
        .unwrap_or_else(|error| panic!("{label}: the link must build a dialer: {error}"));
    let connected = dialer.connect(authority).await;
    let mut stream = match connected {
        Ok(established) => established.stream,
        Err(error) => {
            let server = std::fs::read_to_string(log).unwrap_or_default();
            panic!(
                "{label}: connect failed: {error}\n--- the node said ({}):\n{}",
                log.display(),
                if server.is_empty() {
                    "<nothing>"
                } else {
                    server.trim_end()
                }
            );
        }
    };

    let payload = b"vmess aead speaks";
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

/// A `vmess://` link for this fixture.
///
/// Base64url JSON, which is the reference's share format — the same shape
/// `NodeEndpoint::from_link` parses, so the test exercises that parser too.
fn link(port: u16, cipher: &str, network: &str) -> String {
    let path = if network == "ws" { "/vm" } else { "" };
    let json = format!(
        r#"{{"v":"2","ps":"lab","add":"127.0.0.1","port":"{port}","id":"{UUID}","aid":"0","scy":"{cipher}","net":"{network}","type":"none","host":"","path":"{path}","tls":""}}"#
    );
    format!("vmess://{}", base64(json.as_bytes()))
}

/// URL-safe base64 without padding, which is what a `vmess://` payload is.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let word = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(word >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(word >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(word >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[word as usize & 0x3f] as char);
        }
    }
    out
}

fn skip(test: &str) -> bool {
    if xray().is_some() {
        return false;
    }
    eprintln!(
        "skipping {test}: no `xray` binary on PATH and XRAY_BIN unset. VMess's wire format is only \
         proven by a server that implements it, so a green run without this proves nothing."
    );
    true
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_auto_cipher_carries_a_round_trip() {
    if skip("vmess_auto_cipher_carries_a_round_trip") {
        return;
    }
    let binary = xray().expect("checked above");
    let echo = echo_server().await;
    let (_fixture, port, log) = start(&binary, "auto", "tcp", "");
    assert_round_trip(
        &link(port, "auto", "tcp"),
        &format!("{echo}"),
        "vmess/auto/tcp",
        &log,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_aes_128_gcm_carries_a_round_trip() {
    if skip("vmess_aes_128_gcm_carries_a_round_trip") {
        return;
    }
    let binary = xray().expect("checked above");
    let echo = echo_server().await;
    let (_fixture, port, log) = start(&binary, "aes", "tcp", "");
    assert_round_trip(
        &link(port, "aes-128-gcm", "tcp"),
        &format!("{echo}"),
        "vmess/aes-128-gcm/tcp",
        &log,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_chacha20_poly1305_carries_a_round_trip() {
    // The row that pins `GenerateChacha20Poly1305Key`: a 32-byte key from two MD5 digests, not a
    // SHA-256 prefix. A wrong expansion fails the tag on the node with no attribution.
    if skip("vmess_chacha20_poly1305_carries_a_round_trip") {
        return;
    }
    let binary = xray().expect("checked above");
    let echo = echo_server().await;
    let (_fixture, port, log) = start(&binary, "chacha", "tcp", "");
    assert_round_trip(
        &link(port, "chacha20-poly1305", "tcp"),
        &format!("{echo}"),
        "vmess/chacha20-poly1305/tcp",
        &log,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_with_authenticated_length_carries_a_round_trip() {
    // `AuthenticatedLength` seals the size field, and both ends must have it enabled. This row
    // proves the two sides agree; the row above proves the default still works with the flag off,
    // which is why ADR-0030 makes it explicit rather than always-on.
    if skip("vmess_with_authenticated_length_carries_a_round_trip") {
        return;
    }
    let binary = xray().expect("checked above");
    let echo = echo_server().await;
    let (_fixture, port, log) = start(&binary, "authlen", "tcp", "AuthenticatedLength");

    let options = DialerOptions::new(None, Duration::from_secs(10));
    let mut dialer = ProxyDialer::from_link(&link(port, "auto", "tcp"), options)
        .expect("the link is well formed");
    // The setting is a *node* key, not a link parameter, so it is applied the way a configuration
    // would: rebuild the connector with it.
    let _ = &mut dialer;
    let link = link(port, "auto", "tcp");
    let node = daer_config::NodeEndpoint::from_link(&link).expect("parses");
    let daer_config::NodeEndpoint::Vmess(mut node) = node else {
        panic!("expected a vmess node");
    };
    node.authenticated_length = true;
    let dialer =
        ProxyDialer::from_node(&daer_config::NodeEndpoint::Vmess(node), options).expect("builds");
    let mut stream = match dialer.connect(&format!("{echo}")).await {
        Ok(established) => established.stream,
        Err(error) => {
            let server = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("authlen: connect failed: {error}\n--- the node said:\n{server}");
        }
    };
    let payload = b"authenticated lengths";
    stream.write_all(payload).await.expect("writes");
    stream.flush().await.expect("flushes");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("echo within 10s")
        .expect("reads");
    assert_eq!(&echoed, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_over_websocket_carries_a_round_trip() {
    if skip("vmess_over_websocket_carries_a_round_trip") {
        return;
    }
    let binary = xray().expect("checked above");
    let echo = echo_server().await;
    let (_fixture, port, log) = start(&binary, "ws", "ws", "");
    assert_round_trip(
        &link(port, "auto", "ws"),
        &format!("{echo}"),
        "vmess/auto/ws",
        &log,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_zero_alter_id_is_refused_because_it_selects_the_legacy_handshake() {
    // ADR-0030: only VMess AEAD is implemented, and `aid` is the legacy format's parameter.
    // Accepting a non-zero value while speaking AEAD would be a lie about the wire.
    let json = format!(
        r#"{{"v":"2","add":"127.0.0.1","port":"443","id":"{UUID}","aid":"4","scy":"auto","net":"tcp"}}"#
    );
    let link = format!("vmess://{}", base64(json.as_bytes()));
    let error = ProxyDialer::from_link(&link, DialerOptions::new(None, Duration::from_secs(1)))
        .expect_err("aid=4 selects the legacy handshake");
    let message = error.to_string();
    assert!(message.contains("aid"), "{message}");
    assert!(message.contains("legacy"), "{message}");
}
