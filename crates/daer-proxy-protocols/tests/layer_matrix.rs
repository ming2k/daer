// SPDX-License-Identifier: AGPL-3.0-only

//! The layer matrix, verified against a local `xray` inbound (ADR-0028).
//!
//! # Why this test is the point of ADR-0028
//!
//! Before the refactor there was exactly one reachable combination — `vless` + REALITY
//! (+ Vision, optionally) — because `RealityConnector::from_link` was the only constructor of a
//! VLESS session. Every row below that is not that one was **not expressible**, so nothing
//! could test it. The rows this test adds are the ones the ADR unlocked:
//!
//! | security | transport | flow | before | now |
//! | --- | --- | --- | --- | --- |
//! | `none` | `tcp` | none | unreachable | tested |
//! | `tls` | `tcp` | none | unreachable | tested |
//! | `tls` | `tcp` | vision | unreachable | tested |
//! | `tls` | `ws` | none | unreachable | tested |
//! | `tls` | `ws` | vision | unreachable | tested |
//! | `reality` | `tcp` | none | **tested** | tested |
//! | `reality` | `tcp` | vision | **tested** | tested |
//!
//! # The fixture
//!
//! One `xray` process, one config, four inbounds: plaintext VLESS, VLESS+TLS, VLESS+TLS+Vision,
//! and VLESS+TLS+WebSocket (with and without Vision). Each inbound's user points at a local TCP
//! echo server this test runs, so a successful round trip proves the whole stack rather than the
//! handshake alone.
//!
//! Vision needs a *record layer* to splice, so it is only configured on the TLS and REALITY
//! inbounds — the same restriction the reference enforces (`inbound.go`: "XTLS only supports TLS
//! and REALITY directly for now").
//!
//! # When `xray` is absent
//!
//! The test skips **with a reason** (ADR-0007: a skip that states why is a fact; a pass that
//! proved nothing is a lie). `XRAY_BIN` first, so a developer can point at `../Xray-core/xray`.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use daer_proxy_protocols::{DialerOptions, ProxyDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "df4af3d0-030e-4062-baa6-eb9dd45298ef";

/// The `xray` binary, or `None` when the machine has none.
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
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("binds an ephemeral port")
        .local_addr()
        .expect("has an address")
        .port()
}

/// The certificate a TLS inbound presents, generated once per run.
///
/// Self-signed and thrown away: the node's identity is not what this test is about, and every
/// dial below sets `allow-insecure` so the chain is irrelevant.
fn certificate() -> (String, String) {
    // Keyed on a counter rather than the pid: two tests in one process would otherwise share the
    // directory, and a rerun in a fresh process would point at a path the previous run removed.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("daer-layer-matrix-{}-{index}", std::process::id()));
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
        _ => panic!(
            "this test needs `openssl` on PATH to mint the fixture's certificate; without it the \
             TLS rows cannot be exercised at all"
        ),
    }
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

/// A local TCP echo server, so a successful round trip proves the whole stack.
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

/// The `xray` config that carries every combination this test exercises.
///
/// One inbound per row, all pointing at `echo`, so the round trip is the assertion.
#[allow(clippy::too_many_arguments)]
fn config(
    _echo: SocketAddr,
    cert: &str,
    key: &str,
    plaintext: u16,
    tls: u16,
    tls_vision: u16,
    ws: u16,
    ws_vision: u16,
) -> String {
    let client = format!(
        r#"{{
  "id": "{UUID}",
  "flow": "xtls-rprx-vision",
  "level": 0
}}"#
    );
    let client_no_flow = format!(
        r#"{{
  "id": "{UUID}",
  "level": 0
}}"#
    );
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "plaintext",
      "listen": "127.0.0.1",
      "port": {plaintext},
      "protocol": "vless",
      "settings": {{ "clients": [{client_no_flow}], "decryption": "none" }},
      "streamSettings": {{ "network": "tcp", "security": "none" }}
    }},
    {{
      "tag": "tls",
      "listen": "127.0.0.1",
      "port": {tls},
      "protocol": "vless",
      "settings": {{ "clients": [{client_no_flow}], "decryption": "none" }},
      "streamSettings": {{
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {{ "certificates": [{{ "certificateFile": "{cert}", "keyFile": "{key}" }}] }}
      }}
    }},
    {{
      "tag": "tls-vision",
      "listen": "127.0.0.1",
      "port": {tls_vision},
      "protocol": "vless",
      "settings": {{ "clients": [{client}], "decryption": "none" }},
      "streamSettings": {{
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {{ "certificates": [{{ "certificateFile": "{cert}", "keyFile": "{key}" }}] }}
      }}
    }},
    {{
      "tag": "ws",
      "listen": "127.0.0.1",
      "port": {ws},
      "protocol": "vless",
      "settings": {{ "clients": [{client_no_flow}], "decryption": "none" }},
      "streamSettings": {{
        "network": "ws",
        "security": "tls",
        "tlsSettings": {{ "certificates": [{{ "certificateFile": "{cert}", "keyFile": "{key}" }}] }},
        "wsSettings": {{ "path": "/ray" }}
      }}
    }},
    {{
      "tag": "ws-vision",
      "listen": "127.0.0.1",
      "port": {ws_vision},
      "protocol": "vless",
      "settings": {{ "clients": [{client}], "decryption": "none" }},
      "streamSettings": {{
        "network": "ws",
        "security": "tls",
        "tlsSettings": {{ "certificates": [{{ "certificateFile": "{cert}", "keyFile": "{key}" }}] }},
        "wsSettings": {{ "path": "/ray" }}
      }}
    }}
  ],
  "outbounds": [
    {{ "tag": "freedom", "protocol": "freedom", "settings": {{ "finalRules": [{{ "action": "allow" }}] }} }}
  ]
}}"#
    )
}

/// A running `xray` fixture.
struct Xray {
    child: Child,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `xray` on `config`, waiting until every port answers.
///
/// The wait is a connect loop rather than a sleep: a fixed sleep is either too short (a flaky
/// test) or too long (a slow suite), and the ports answering is exactly the condition the test
/// needs.
fn start(xray: &PathBuf, config: &str, ports: &[u16]) -> Xray {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "daer-layer-matrix-{}-{index}-cfg",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("creates a temp dir");
    let path = dir.join("config.json");
    let mut file = std::fs::File::create(&path).expect("creates the config");
    file.write_all(config.as_bytes())
        .expect("writes the config");

    let child = Command::new(xray)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns xray");

    let fixture = Xray { child };
    let deadline = Instant::now() + Duration::from_secs(10);
    for port in ports {
        loop {
            if TcpStream::connect(("127.0.0.1", *port)).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "xray never listened on port {port} (config at {})",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fixture
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

    let payload = b"the layer matrix speaks";
    stream
        .write_all(payload)
        .await
        .unwrap_or_else(|error| panic!("{label}: write failed: {error}"));
    stream
        .flush()
        .await
        .unwrap_or_else(|error| panic!("{label}: flush failed: {error}"));

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .unwrap_or_else(|_| panic!("{label}: no echo within 5s"))
        .unwrap_or_else(|error| panic!("{label}: read failed: {error}"));
    assert_eq!(&echoed, payload, "{label}: the echo must match");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_layer_combination_carries_a_round_trip() {
    let Some(xray) = xray() else {
        eprintln!(
            "skipping every_layer_combination_carries_a_round_trip: no `xray` binary on PATH and \
             XRAY_BIN unset. This is the test that proves the layer matrix works, so a green run \
             without it proves nothing about the wire."
        );
        return;
    };

    let echo = echo_server().await;
    let (cert, key) = certificate();
    let plaintext = free_port();
    let tls = free_port();
    let tls_vision = free_port();
    let ws = free_port();
    let ws_vision = free_port();

    let fixture = start(
        &xray,
        &config(echo, &cert, &key, plaintext, tls, tls_vision, ws, ws_vision),
        &[plaintext, tls, tls_vision, ws, ws_vision],
    );

    let authority = format!("{echo}");

    // ── 1. vless over plaintext ─────────────────────────────────────────────
    // Unreachable before ADR-0028: the only VLESS constructor required `security=reality`.
    assert_round_trip(
        &format!("vless://{UUID}@127.0.0.1:{plaintext}?encryption=none&security=none&type=tcp"),
        &authority,
        "vless/none/tcp",
    )
    .await;

    // ── 2. vless over TLS ───────────────────────────────────────────────────
    assert_round_trip(
        &format!(
            "vless://{UUID}@127.0.0.1:{tls}?encryption=none&security=tls&sni=lab.example.com\
             &allowInsecure=1&type=tcp"
        ),
        &authority,
        "vless/tls/tcp",
    )
    .await;

    // ── 3. vless over TLS with Vision ───────────────────────────────────────
    // The flow used to be reachable only through REALITY; this is the row the refactor unlocked.
    assert_round_trip(
        &format!(
            "vless://{UUID}@127.0.0.1:{tls_vision}?encryption=none&security=tls\
             &sni=lab.example.com&allowInsecure=1&type=tcp&flow=xtls-rprx-vision"
        ),
        &authority,
        "vless/tls/tcp/vision",
    )
    .await;

    // ── 4. vless over TLS over WebSocket ────────────────────────────────────
    // `type=ws` was a load error before; the transport layer is now its own axis.
    assert_round_trip(
        &format!(
            "vless://{UUID}@127.0.0.1:{ws}?encryption=none&security=tls&sni=lab.example.com\
             &allowInsecure=1&type=ws&path=%2Fray&host=lab.example.com"
        ),
        &authority,
        "vless/tls/ws",
    )
    .await;

    // ── 5. vless over TLS over WebSocket with Vision is REFUSED ─────────────
    // Not a gap in daer: the reference refuses it on *both* ends. Xray's inbound checks the outer
    // connection with a type assertion — `*tls.Conn` or `*reality.UConn` — and a `ws`-wrapped
    // connection is neither, so it answers "XTLS only supports TLS and REALITY directly for now".
    // Vision splices the record layer, and a transport between the two puts something in the way.
    //
    // The fixture *does* configure this inbound, which is the point: the refusal has to be daer's
    // own load-time error, not a node rejecting a valid-looking session.
    let _ = ws_vision;
    let error = ProxyDialer::from_link(
        &format!(
            "vless://{UUID}@127.0.0.1:{ws_vision}?encryption=none&security=tls\
             &sni=lab.example.com&allowInsecure=1&type=ws&path=%2Fray\
             &flow=xtls-rprx-vision"
        ),
        DialerOptions::new(None, Duration::from_secs(5)),
    )
    .expect_err("vision over ws must be refused at load");
    let message = error.to_string();
    assert!(message.contains("xtls-rprx-vision"), "{message}");
    assert!(
        message.contains("directly under the protocol")
            || message.contains("wraps the record layer"),
        "the refusal must say why: {message}"
    );

    drop(fixture);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_security_layer_the_node_does_not_have_fails_rather_than_silently_succeeding() {
    // The falsifier for the matrix above: if every row passed regardless of the inbound, the
    // matrix would prove nothing. This dials the *plaintext* inbound with `security=tls`, which
    // must fail — a plaintext VLESS listener answers a TLS ClientHello with a VLESS rejection.
    let Some(xray) = xray() else {
        eprintln!("skipping a_security_layer_the_node_does_not_have_fails: no `xray` binary.");
        return;
    };
    let echo = echo_server().await;
    let (cert, key) = certificate();
    let plaintext = free_port();
    let tls = free_port();
    let tls_vision = free_port();
    let ws = free_port();
    let ws_vision = free_port();
    let _fixture = start(
        &xray,
        &config(echo, &cert, &key, plaintext, tls, tls_vision, ws, ws_vision),
        &[plaintext, tls, tls_vision, ws, ws_vision],
    );

    let options = DialerOptions::new(None, Duration::from_secs(3));
    let link = format!(
        "vless://{UUID}@127.0.0.1:{plaintext}?encryption=none&security=tls&sni=lab.example.com\
         &allowInsecure=1&type=tcp"
    );
    let dialer = ProxyDialer::from_link(&link, options).expect("the link is well formed");
    let error = match dialer.connect(&format!("{echo}")).await {
        Ok(_) => panic!("a plaintext listener must not complete a TLS handshake"),
        Err(error) => error,
    };
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("handshake") || message.contains("tls") || message.contains("time"),
        "the failure must name the handshake: {error}"
    );

    // The control: the same node over `security=none` does work, so the failure above is the
    // security layer and not the node.
    let link =
        format!("vless://{UUID}@127.0.0.1:{plaintext}?encryption=none&security=none&type=tcp");
    assert_round_trip(&link, &format!("{echo}"), "control vless/none/tcp").await;
}
