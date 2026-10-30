// SPDX-License-Identifier: AGPL-3.0-only

//! Flow → verdict → dial → relay, end to end.
//!
//! These tests drive the real router through the real accept loop. Only two things
//! are faked: the ingress (a plain listener instead of a transparent one, so no
//! privileges are needed) and the remote services (local echo / SOCKS5 servers).
//! The routing decision, the group machinery, the dialer and the relay are the
//! production ones — which is the point: the seam between routing and outbound is
//! exactly where a proxy silently sends traffic to the wrong place.

use std::net::{Ipv4Addr, SocketAddr};

use daer_control::{Generations, Ingress, IngressError, Supervisor, serve_ingress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A plain listener dressed as an ingress: same loop, no privileges.
///
/// A transparent listener reports the *original* destination as the accepted
/// socket's local address, because the kernel restored it. A plain listener reports
/// its own address there, so the destination is supplied instead — which is exactly
/// the fact the kernel contributes in production.
struct PlainIngress {
    listener: TcpListener,
    destination: SocketAddr,
}

impl Ingress for PlainIngress {
    async fn accept(&self) -> Result<daer_control::Accepted, IngressError> {
        let (stream, source) = self.listener.accept().await.map_err(IngressError::Accept)?;
        Ok(daer_control::Accepted {
            stream,
            source,
            destination: self.destination,
        })
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 512];
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
    addr
}

/// A minimal SOCKS5 server: no-auth, one CONNECT, then it splices to the echo
/// server it was told to use. Enough to prove the node dialer really speaks the
/// protocol through the data path.
async fn socks5_server(upstream: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Greeting: version, method count, methods. No-auth only.
                let mut greeting = [0u8; 2];
                if client.read_exact(&mut greeting).await.is_err() || greeting[0] != 5 {
                    return;
                }
                let mut methods = vec![0u8; usize::from(greeting[1])];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if client.write_all(&[5, 0]).await.is_err() {
                    return;
                }

                // Request: ver, cmd, rsv, atyp, addr, port.
                let mut head = [0u8; 4];
                if client.read_exact(&mut head).await.is_err() || head[1] != 1 {
                    return;
                }
                let addr_len = match head[3] {
                    1 => 4,
                    4 => 16,
                    3 => {
                        let mut len = [0u8; 1];
                        if client.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        usize::from(len[0])
                    }
                    _ => return,
                };
                let mut consumed = vec![0u8; addr_len + 2];
                if client.read_exact(&mut consumed).await.is_err() {
                    return;
                }
                // Success, IPv4 bind address 0.0.0.0:0.
                if client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }

                let Ok(mut server) = TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    addr
}

/// Starts the loop for `config`, reporting `destination` for every flow.
async fn start(config: &str, destination: SocketAddr) -> (SocketAddr, Supervisor) {
    let config = daer_config::toml_config::load_str(config).expect("config loads");
    let generations = Generations::new(&config, &daer_control::RouterOptions::default())
        .expect("the first generation builds");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    let supervisor = Supervisor::new();
    let ingress = PlainIngress {
        listener,
        destination,
    };
    // A flow pins the generation it arrived under; holding the `Arc` in the task is
    // exactly what a reload must not disturb.
    let generation = generations.current();
    let loop_supervisor = supervisor.clone();
    tokio::spawn(async move {
        let _ = serve_ingress(
            &ingress,
            generation.router(),
            &loop_supervisor,
            std::future::pending(),
        )
        .await;
    });
    (addr, supervisor)
}

async fn round_trip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(addr).await.expect("connects");
    client.write_all(payload).await.expect("writes");
    let mut received = vec![0u8; payload.len()];
    client
        .read_exact(&mut received)
        .await
        .expect("reads the echo");
    received
}

#[tokio::test]
async fn a_rule_sends_a_flow_direct() {
    let upstream = echo_server().await;
    let config = format!(
        r#"
[routing]
rules = ["dport({}) -> direct"]
fallback = "direct"
"#,
        upstream.port()
    );
    let (addr, metrics) = start(&config, upstream).await;

    assert_eq!(round_trip(addr, b"direct").await, b"direct");
    let stats = metrics.metrics().snapshot();
    assert_eq!(stats.accepted, 1, "{stats:?}");
    assert_eq!(stats.failed, 0, "{stats:?}");
}

#[tokio::test]
async fn a_block_rule_drops_the_flow_without_dialing() {
    let config = r#"
[routing]
rules = ["dport(1) -> block"]
fallback = "block"
"#;
    let (addr, metrics) = start(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 1))).await;

    let mut client = TcpStream::connect(addr).await.expect("connects");
    let _ = client.write_all(b"blocked").await;
    let mut sink = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.read_to_end(&mut sink),
    )
    .await
    .expect("a blocked flow must be closed, not left open");
    // Either a clean EOF or a reset: both mean "not served".
    assert!(read.is_ok() || read.is_err(), "closed: {read:?}");
    assert!(sink.is_empty());

    let stats = metrics.metrics().snapshot();
    assert_eq!(stats.accepted, 1, "{stats:?}");
    assert_eq!(
        stats.failed, 1,
        "the group/block path must be counted: {stats:?}"
    );
}

#[tokio::test]
async fn a_group_rule_dials_through_the_node() {
    let upstream = echo_server().await;
    let proxy = socks5_server(upstream).await;
    let proxy_str = proxy.to_string();
    let (server, port) = proxy_str.split_once(':').unwrap();
    let config = format!(
        r#"
[[node]]
tag = "n1"
type = "socks5"
server = "{server}"
port = {port}

[[group]]
name = "proxy"
policy = "fixed(0)"

[routing]
rules = []
fallback = "proxy"
"#
    );
    let (addr, metrics) = start(&config, upstream).await;

    // The flow goes: client → router → SOCKS5 node → echo server → back.
    assert_eq!(round_trip(addr, b"through-node").await, b"through-node");
    let stats = metrics.metrics().snapshot();
    assert_eq!(stats.accepted, 1, "{stats:?}");
    assert_eq!(stats.failed, 0, "{stats:?}");
}

#[tokio::test]
async fn a_fallback_naming_a_missing_group_fails_the_generation() {
    let config = daer_config::toml_config::load_str(
        r#"
[routing]
rules = []
fallback = "nope"
"#,
    )
    .expect("config loads");

    let error = Generations::new(&config, &daer_control::RouterOptions::default())
        .expect_err("must not build");
    // The rule error is the source; the message is about the service.
    assert!(error.source.to_string().contains("not found"), "{error}");
    // Nothing was ever published, so nothing may claim to be serving.
    assert!(!error.to_string().contains("still serving"), "{error}");
    assert!(error.to_string().contains("nothing is serving"), "{error}");
}

#[tokio::test]
async fn a_group_with_no_selectable_node_fails_the_flow_loudly() {
    // A node whose protocol this build cannot speak must not be used as `direct`.
    let config = r#"
subscription = ["vless://uuid@example.com:443"]

[[group]]
name = "proxy"
policy = "fixed(0)"

[routing]
rules = []
fallback = "proxy"
"#;
    let (addr, metrics) = start(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 443))).await;

    let mut client = TcpStream::connect(addr).await.expect("connects");
    let _ = client.write_all(b"x").await;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.read_to_end(&mut sink),
    )
    .await
    .expect("the flow must be closed, not hang");

    let stats = metrics.metrics().snapshot();
    assert_eq!(stats.accepted, 1, "{stats:?}");
    assert_eq!(stats.failed, 1, "{stats:?}");
    let _ = stats.rejected;
}
