// SPDX-License-Identifier: AGPL-3.0-only

//! REALITY + Vision interop against a **local** `xray` inbound that this test starts.
//!
//! # Why this exists next to `reality_live.rs`
//!
//! `reality_live.rs` needs a credentialed public node and is `#[ignore]`, so it never runs
//! in CI. That left the single most damaging defect in this crate undetected: a REALITY
//! session authenticated correctly, the node wrote its reply, and the client reported
//! **EOF** before reading a byte — because a zero-length `application_data` record was
//! returned as `Ready(Ok(()))` with nothing written. Every proxied connection through every
//! REALITY node was dead, while `docs/dev/roadmap.md` called REALITY "live-verified".
//!
//! This test closes that gap the way `docs/dev/standards/testing.md` §2.2 requires: a local
//! server, not a public one, so it is a fixture rather than a dependency on someone else's
//! uptime. It starts `xray` itself, and **skips with a reason** when `xray` is not installed
//! (ADR-0007: a skip that states why is a fact; a pass that proved nothing is a lie).
//!
//! ```sh
//! cargo test -p daer-outbound --test reality_interop -- --nocapture
//! XRAY_BIN=/path/to/xray cargo test -p daer-outbound --test reality_interop
//! ```
//!
//! # The encodings this pins
//!
//! The fixture is the reference implementation, so this is a differential test rather than
//! an assertion about our own idea of the protocol. It covers the three layers that failed
//! silently and separately:
//!
//! 1. **REALITY authentication** — the tag in `legacy_session_id`. A wrong one makes the
//!    node *forward* the flow to the impersonated site, which yields a valid TLS 1.3
//!    handshake against a host nobody asked for. `reality/verify.rs` is what turns that into
//!    an explicit failure, and [`a_plain_tcp_server_is_not_accepted_as_a_reality_node`]
//!    proves the check can fail at all.
//! 2. **The VLESS request header** — `PortThenAddress`, so a wrong byte order dials a
//!    garbage address and the node resets.
//! 3. **Vision framing** — the opening long-padded block and the `End` command on the first
//!    payload. A malformed block is treated as payload by the peer, so the stream corrupts
//!    instead of erroring.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use daer_outbound::{DialerOptions, NodeDialer};

/// The `xray` binary, or `None` when the machine has none.
///
/// `XRAY_BIN` first so a developer can point at a checkout build (`../Xray-core/xray`),
/// then `PATH`. Returning `None` is what turns the test into a stated skip.
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

/// A port nobody is listening on, obtained by letting the kernel choose one.
///
/// The socket is closed before the server binds it, so this is a race in principle. It is
/// the usual trade and the window is microseconds; the alternative — a fixed port — fails
/// every time two test runs overlap, which is worse.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("binds an ephemeral port")
        .local_addr()
        .expect("has an address")
        .port()
}

/// `xray x25519` output: the key pair the REALITY inbound and the link must agree on.
struct Keys {
    private: String,
    public: String,
}

fn generate_keys(xray: &PathBuf) -> Keys {
    let output = Command::new(xray)
        .arg("x25519")
        .output()
        .expect("runs `xray x25519`");
    assert!(
        output.status.success(),
        "`xray x25519` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let field = |label: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(label).map(str::trim))
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("`xray x25519` printed no {label:?}:\n{text}"))
    };
    Keys {
        private: field("PrivateKey:"),
        public: field("Password (PublicKey):"),
    }
}

/// A running `xray` inbound, killed when this value drops.
///
/// RAII rather than a `kill` at the end of the test: a panic between the two would leave a
/// listener on the machine and make the *next* run fail for a reason that has nothing to do
/// with the code under test.
struct Server {
    child: Child,
    log: PathBuf,
}

impl Server {
    /// Starts a REALITY inbound on `port` with Vision enabled for `uuid`.
    fn start(
        xray: &PathBuf,
        port: u16,
        uuid: &str,
        keys: &Keys,
        dest: &str,
        short_id: &str,
    ) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "daer-reality-interop-{}-{port}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates the fixture directory");
        let config = dir.join("server.json");
        let log = dir.join("server.log");

        // `show: true` is what makes the server print its REALITY verdict; without it a
        // forwarded flow and an authenticated one look identical from the outside.
        let json = format!(
            r#"{{
  "log": {{ "loglevel": "debug" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {port}, "protocol": "vless",
    "settings": {{
      "clients": [{{ "id": "{uuid}", "flow": "xtls-rprx-vision" }}],
      "decryption": "none"
    }},
    "streamSettings": {{
      "network": "tcp", "security": "reality",
      "realitySettings": {{
        "show": true,
        "dest": "{dest}",
        "serverNames": ["{name}"],
        "privateKey": "{private}",
        "shortIds": ["{short_id}"]
      }}
    }}
  }}],
  "outbounds": [{{ "protocol": "freedom" }}]
}}"#,
            name = dest.rsplit_once(':').map_or(dest, |(host, _)| host),
            private = keys.private,
        );
        std::fs::write(&config, json).expect("writes the fixture config");

        let child = Command::new(xray)
            .arg("run")
            .arg("-c")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawns xray");

        let server = Self { child, log };
        server.await_ready(port, &config);
        server
    }

    /// Blocks until the inbound accepts, so a test never races the server's startup.
    fn await_ready(&self, port: u16, config: &std::path::Path) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().expect("address"),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        panic!(
            "xray never listened on {port}; config {} ; log:\n{log}",
            config.display()
        );
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(self.log.parent().unwrap_or(&self.log));
        let _ = std::fs::remove_file(&self.log);
    }
}

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_secs(10))
}

/// The link for a node this test started, as a subscription would spell it.
fn link(port: u16, uuid: &str, public: &str, sni: &str, short_id: &str) -> String {
    format!(
        "vless://{uuid}@127.0.0.1:{port}?encryption=none&security=reality&flow=xtls-rprx-vision\
         &sni={sni}&pbk={public}&sid={short_id}&type=tcp&fp=chrome#interop"
    )
}

const UUID: &str = "df4af3d0-030e-4062-baa6-eb9dd45298ef";
const SHORT_ID: &str = "8e3af867d5ffc09f";

/// A real site on 443 for the node to impersonate.
///
/// REALITY mimics the target's handshake record lengths, so this cannot be a local
/// `openssl s_server`: a too-small certificate makes the *server* fail its own padding check
/// (`payload[0]: 8, padding: -4`), which is a fixture fault that reads like a client bug.
fn dest() -> String {
    std::env::var("DAER_REALITY_DEST").unwrap_or_else(|_| "www.microsoft.com:443".to_owned())
}

/// The whole point: a REALITY + Vision session must carry bytes in **both** directions.
///
/// The falsifier is the EOF defect: the client used to return success from `connect` and
/// then read zero bytes, because the zero-length record the node flushes after the handshake
/// was reported as end-of-stream. Asserting `read > 0` alone would not have been enough —
/// the assertion is on the *content*, so a Vision reply that still carried its block header
/// also fails.
#[tokio::test(flavor = "current_thread")]
async fn a_reality_vision_session_carries_bytes_both_ways() {
    let Some(xray) = xray() else {
        eprintln!("skipped: no `xray` binary (set XRAY_BIN to a reference build)");
        return;
    };
    let keys = generate_keys(&xray);
    let port = free_port();
    let dest = dest();
    let sni = dest
        .rsplit_once(':')
        .map_or(dest.as_str(), |(host, _)| host);
    let _server = Server::start(&xray, port, UUID, &keys, &dest, SHORT_ID);

    let dialer = NodeDialer::from_link(&link(port, UUID, &keys.public, sni, SHORT_ID), options())
        .expect("the link must parse");

    // `example.com:80` is the address asked of the *node*: the VLESS header carries it, so
    // the node dials it. A plain HTTP/1.1 request then proves the tunnel carries bytes.
    let established =
        tokio::time::timeout(Duration::from_secs(20), dialer.connect("example.com:80"))
            .await
            .expect("the connect must not hang")
            .expect("the session must be established and the node must authenticate itself");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = established.stream;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("the request must be written");

    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut reply))
        .await
        .expect("the reply must not hang")
        .expect("the reply must be readable");

    assert!(
        !reply.is_empty(),
        "the tunnel carried nothing back; the node's own log said:\n{}",
        _server.log()
    );
    assert!(
        reply.starts_with(b"HTTP/1."),
        "the reply is not a bare HTTP response: {:?}",
        String::from_utf8_lossy(&reply[..reply.len().min(64)])
    );
}

/// ADR-0007's negative control for the test above: the authentication check must be able to
/// **fail**.
///
/// A weak client accepts anything that completes a TLS 1.3 handshake. The local inbound with
/// a *wrong* public key is exactly what a forwarded flow looks like: the handshake completes
/// against the impersonated site, and only `reality/verify.rs` can tell the difference. If
/// this test ever passes, the previous one proves nothing — it would accept any server that
/// can present a certificate.
#[tokio::test(flavor = "current_thread")]
async fn a_wrong_public_key_is_refused_rather_than_forwarded() {
    let Some(xray) = xray() else {
        eprintln!("skipped: no `xray` binary (set XRAY_BIN to a reference build)");
        return;
    };
    let keys = generate_keys(&xray);
    let other = generate_keys(&xray);
    let port = free_port();
    let dest = dest();
    let sni = dest
        .rsplit_once(':')
        .map_or(dest.as_str(), |(host, _)| host);
    let _server = Server::start(&xray, port, UUID, &keys, &dest, SHORT_ID);

    // The server holds `keys.private`; the link claims `other.public`. The tag cannot be
    // opened, so the node forwards the flow instead of accepting it.
    let dialer = NodeDialer::from_link(
        &link(port, UUID, &other.public, sni, SHORT_ID),
        DialerOptions::new(None, Duration::from_secs(10)),
    )
    .expect("the link must parse");

    let error = tokio::time::timeout(Duration::from_secs(20), dialer.connect("example.com:80"))
        .await
        .expect("the connect must not hang")
        .err()
        .expect("a flow the node cannot authenticate must not be accepted");
    let message = error.to_string();
    assert!(
        message.contains("not the REALITY node")
            || message.contains("certificate")
            || message.contains("the peer closed")
            || message.contains("no answer"),
        "the failure must name the authentication, not something downstream: {message}"
    );
}

/// A second negative control: a server that speaks no REALITY at all must be refused.
///
/// This is the coarsest possible "is the check wired up" probe. A plain TCP listener accepts
/// the connection and answers nothing, so a client that only waited for `connect` to return
/// would report success and then hang. The assertion is that `connect` fails instead.
#[tokio::test(flavor = "current_thread")]
async fn a_plain_tcp_server_is_not_accepted_as_a_reality_node() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
    let port = listener.local_addr().expect("address").port();
    // Accept and immediately close: a REALITY handshake needs a flight in reply, and this
    // gives none. The thread ends when the listener does.
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"not a tls record at all");
        }
    });

    let link = link(
        port,
        UUID,
        "Wz4Tvu40MhBeystLVkqKKnpkphWJj6pmL9bAmmuzM1w",
        "www.microsoft.com",
        SHORT_ID,
    );
    let dialer = NodeDialer::from_link(&link, DialerOptions::new(None, Duration::from_secs(5)))
        .expect("the link must parse");
    let error = tokio::time::timeout(Duration::from_secs(20), dialer.connect("example.com:80"))
        .await
        .expect("the connect must not hang")
        .err()
        .expect("a server that does not speak REALITY must be refused");
    assert!(
        !error.to_string().is_empty(),
        "the refusal must carry a reason"
    );
    let _ = handle.join();
}
