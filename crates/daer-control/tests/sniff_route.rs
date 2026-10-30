// SPDX-License-Identifier: AGPL-3.0-only

//! Sniffing feeds routing: the name in the ClientHello decides the outbound.
//!
//! This is the exit criterion of the sniffer written as a test — a flow whose IP matches
//! nothing becomes routable by the domain the client actually asked for, and the bytes
//! still reach the origin byte-for-byte.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use daer_control::{Generations, Ingress, IngressError, RouterOptions, Supervisor, serve_ingress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sni_body = Vec::new();
    sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_body.push(0);
    sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_body);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    let length = body.len();
    handshake.extend_from_slice(&[
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Records what the origin received, so the test can prove nothing was consumed.
async fn recording_origin() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = listener.local_addr().expect("addr");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut buffer = vec![0u8; 4096];
        let read = stream.read(&mut buffer).await.expect("reads");
        let _ = sender.send(buffer[..read].to_vec());
        // Keep the connection open so the relay does not end before the assertion.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    (address, receiver)
}

async fn start(config: &str, destination: SocketAddr) -> (SocketAddr, Supervisor) {
    let config = daer_config::toml_config::load_str(config).expect("config loads");
    let generations = Generations::new(&config, &RouterOptions::default()).expect("builds");
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = probe.local_addr().expect("addr");
    drop(probe);

    let listener = TcpListener::bind(address).await.expect("rebinds");
    let supervisor = Supervisor::new();
    let ingress = PlainIngress {
        listener,
        destination,
    };
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
    (address, supervisor)
}

#[tokio::test]
async fn a_domain_rule_routes_a_flow_that_matched_no_ip_rule() {
    let (origin, received) = recording_origin().await;
    // The IP-only rules cannot match this destination, so without sniffing the flow would
    // fall through to the fallback. The domain rule is what decides it.
    let config = r#"
[global]
sniffing-timeout = "200ms"

[routing]
rules = [
    "dip(10.0.0.0/8) -> block",
    "domain(suffix: sniffed.example) -> direct",
]
fallback = "block"
"#;
    let (address, supervisor) = start(config, origin).await;

    let mut client = TcpStream::connect(address).await.expect("connects");
    let hello = client_hello_with_sni("www.sniffed.example");
    client.write_all(&hello).await.expect("writes");

    // The origin receives the ClientHello unchanged: sniffing peeked, never consumed.
    let payload = tokio::time::timeout(Duration::from_secs(5), received)
        .await
        .expect("the origin must be reached")
        .expect("the origin reported");
    assert_eq!(payload, hello, "peeking must not alter the stream");

    let stats = supervisor.metrics().snapshot();
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.failed, 0, "the domain rule won: {stats:?}");
}

#[tokio::test]
async fn without_a_matching_domain_the_fallback_applies() {
    let (origin, _received) = recording_origin().await;
    let config = r#"
[global]
sniffing-timeout = "200ms"

[routing]
rules = ["domain(suffix: sniffed.example) -> direct"]
fallback = "block"
"#;
    let (address, supervisor) = start(config, origin).await;

    let mut client = TcpStream::connect(address).await.expect("connects");
    // A name the rule does not match: the fallback blocks it.
    client
        .write_all(&client_hello_with_sni("elsewhere.example"))
        .await
        .expect("writes");

    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut sink)).await;
    let stats = supervisor.metrics().snapshot();
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.failed, 1, "the fallback blocked it: {stats:?}");
}

#[tokio::test]
async fn a_configuration_without_domain_rules_does_not_pay_for_sniffing() {
    let (origin, received) = recording_origin().await;
    let config = r#"
[routing]
rules = ["port(443) -> direct"]
fallback = "direct"
"#;
    let (address, _supervisor) = start(config, origin).await;

    let mut client = TcpStream::connect(address).await.expect("connects");
    let hello = client_hello_with_sni("no-sniff.example");
    client.write_all(&hello).await.expect("writes");

    // Leading with a TLS record costs nothing: the flow is relayed immediately.
    let payload = tokio::time::timeout(Duration::from_secs(3), received)
        .await
        .expect("no sniff delay")
        .expect("the origin reported");
    assert_eq!(payload, hello);
}
