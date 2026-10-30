// SPDX-License-Identifier: AGPL-3.0-only

//! Subscription resolution against a real HTTP server.
//!
//! These drive the whole path: an HTTP server on a loopback port, the owned
//! `netune` client, base64 decoding, the cache, and the node pool that a group
//! finally selects from. Only the node *protocols* are real (an `ss://` link is
//! parsed by the production parser); no proxy connection is opened, because the
//! question here is "does a subscription become selectable nodes", not "does
//! shadowsocks work".

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use daer_control::resolve_subscriptions_with;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves one body for every request, then keeps the connection open until the
/// client closes it.
async fn serve_once(body: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                // Read the request head; the body is irrelevant to the response but
                // the client will not start reading until the head is consumed.
                let mut buffer = [0u8; 4096];
                let mut seen = 0usize;
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            seen += read;
                            if buffer[..read]
                                .windows(4)
                                .any(|window| window == b"\r\n\r\n")
                            {
                                break;
                            }
                            if seen > 64 * 1024 {
                                return;
                            }
                        }
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
                    body.len()
                );
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

fn base64(input: &[u8]) -> String {
    const PAD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(PAD[((value >> (18 - index * 6)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn config(url: &str) -> daer_config::Config {
    daer_config::toml_config::load_str(&format!(
        "schema = 1\n[[subscription]]\ntag = \"airport\"\nurl = \"{url}\"\npersist = true\n"
    ))
    .expect("config")
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let directory =
        std::env::temp_dir().join(format!("daer-sub-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("creates");
    directory
}

#[tokio::test]
async fn a_base64_subscription_becomes_a_node_pool() {
    let body = base64(
        b"ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#tokyo\n\
          ss://YWVzLTI1Ni1nY206cHc@5.6.7.8:8388#osaka\n\
          trojan://pw@node.example.com:443?sni=node.example.com#t1",
    );
    let address = serve_once(body.into_bytes()).await;
    let directory = temp_dir("base64");

    let mut configuration = config(&format!("http://{address}/sub"));
    let resolution =
        resolve_subscriptions_with(&mut configuration, &directory, Duration::from_secs(5)).await;

    assert!(resolution.all_usable(), "{resolution:?}");
    assert_eq!(resolution.from_subscription, 3);
    assert_eq!(configuration.node.len(), 3);
    // The tag is what `subtag(...)` filters match on, so every node must carry one
    // derived from its subscription.
    for node in &configuration.node {
        let tag = node.tag.as_deref().expect("tagged");
        assert!(tag.starts_with("airport/"), "{tag}");
    }
    // And every fetched link must be one the production parser accepts.
    for node in &configuration.node {
        daer_outbound::NodeDialer::from_link(
            &node.url,
            daer_outbound::DialerOptions::new(None, Duration::from_secs(1)),
        )
        .expect("the fetched link is usable");
    }

    // The fetch was persisted, so the next start survives the endpoint going away.
    let cache = daer_outbound::subscription::Cache::new(
        daer_control::cache_directory(&directory),
        "airport",
    );
    assert_eq!(cache.read().expect("read").expect("present").len(), 3);
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn a_sip008_subscription_becomes_shadowsocks_nodes() {
    let body = r#"{"version":1,"servers":[
        {"id":"a","remarks":"Tokyo","server":"1.2.3.4","server_port":8388,
         "method":"aes-256-gcm","password":"pw"},
        {"id":"b","remarks":"Osaka","server":"5.6.7.8","server_port":8388,
         "method":"chacha20-ietf-poly1305","password":"pw"}
    ]}"#;
    let address = serve_once(body.as_bytes().to_vec()).await;
    let directory = temp_dir("sip008");

    let mut configuration = config(&format!("http://{address}/sub"));
    let resolution =
        resolve_subscriptions_with(&mut configuration, &directory, Duration::from_secs(5)).await;

    assert_eq!(
        resolution.subscriptions[0].format,
        Some(daer_outbound::subscription::Format::Sip008)
    );
    assert_eq!(configuration.node.len(), 2);
    for node in &configuration.node {
        let property = daer_outbound::Property::from_link(&node.url, &node.url, "");
        assert_eq!(property.protocol, daer_outbound::Protocol::ShadowSocks);
    }
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn the_cache_survives_the_endpoint_dying() {
    let body = base64(b"ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#tokyo");
    let address = serve_once(body.into_bytes()).await;
    let directory = temp_dir("survive");

    let mut first = config(&format!("http://{address}/sub"));
    let resolution =
        resolve_subscriptions_with(&mut first, &directory, Duration::from_secs(5)).await;
    assert_eq!(resolution.from_subscription, 1);

    // Now the endpoint refuses: port 1 on loopback, no server.
    let mut second = config("http://127.0.0.1:1/sub");
    let resolution =
        resolve_subscriptions_with(&mut second, &directory, Duration::from_millis(500)).await;

    assert_eq!(second.node.len(), 1, "the cache supplied the node");
    assert!(resolution.subscriptions[0].from_cache);
    assert!(resolution.all_usable());
    assert!(
        resolution.subscriptions[0].error.is_some(),
        "the fetch failure is reported alongside the cached nodes"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn an_http_error_does_not_replace_a_good_cache() {
    // The failure that would silently break an operator's proxy at the next
    // restart: the endpoint returns an error page and the cache is clobbered.
    let directory = temp_dir("error-page");
    let cache = daer_outbound::subscription::Cache::new(
        daer_control::cache_directory(&directory),
        "airport",
    );
    cache
        .write(&["ss://YWVzLTI1Ni1nY206cHc@9.9.9.9:8388#good".to_owned()])
        .expect("writes");

    // A server that answers 200 with an HTML page: decode fails, so nothing is
    // persisted and the old cache must still be there.
    let address = serve_once(b"<html>subscription expired</html>".to_vec()).await;
    let mut configuration = config(&format!("http://{address}/sub"));
    let resolution =
        resolve_subscriptions_with(&mut configuration, &directory, Duration::from_secs(5)).await;

    assert_eq!(
        configuration.node.len(),
        1,
        "the cache still supplies a node"
    );
    assert!(resolution.subscriptions[0].from_cache);
    assert_eq!(
        cache.read().expect("read").expect("present"),
        ["ss://YWVzLTI1Ni1nY206cHc@9.9.9.9:8388#good"],
        "the undecodable body must not overwrite the cache"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn a_subscription_with_no_usable_node_is_not_a_silent_empty_group() {
    // Every node is a protocol this build cannot speak: the resolution must report
    // zero nodes rather than a pool that looks populated.
    let body = base64(b"vmess://eyJhZGQiOiJ4In0\nvless://uuid@example.com:443");
    let address = serve_once(body.into_bytes()).await;
    let directory = temp_dir("unusable");

    let mut configuration = config(&format!("http://{address}/sub"));
    let resolution =
        resolve_subscriptions_with(&mut configuration, &directory, Duration::from_secs(5)).await;

    // The links decode (both are well-formed), so they enter the pool; it is the
    // *generation builder* that refuses them, and `daer config validate` that
    // reports it. Here the resolution itself must still be honest about what it got.
    assert_eq!(resolution.from_subscription, 2);
    assert!(resolution.all_usable());
    for node in &configuration.node {
        assert!(
            daer_outbound::NodeDialer::from_link(
                &node.url,
                daer_outbound::DialerOptions::new(None, Duration::from_secs(1)),
            )
            .is_err(),
            "this build must not claim to speak {}",
            node.url
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
}
