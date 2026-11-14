// SPDX-License-Identifier: AGPL-3.0-only

//! Resolving `[[node]] detour = "<name>"` edges into a usable dialer graph.
//!
//! # Why resolution is a separate pass
//!
//! A detour edge points forward, backward, or into a node supplied by a subscription; neither
//! declaration order nor a single pass over the list can decide whether it is usable. This
//! module turns the flat pool into a DAG once per generation:
//!
//! ```text
//!   target ──▶ node B ──▶ node A
//!                 ▲          │
//!                 └── detour ┘
//! ```
//!
//! Each node is built at most once and shared through `Arc`: a chain of ten nodes is ten
//! dialers, not ten copies per group. Cycles are rejected by both `daer-config`'s graph
//! validator and this builder (the second check is defensive, not a second policy).
//!
//! # What it deliberately does not support
//!
//! A detour names a **node**, not a group. A group chooses a node per flow; a chain whose hop
//! is chosen per flow cannot be validated as a DAG, probed as a unit, or explained as a fixed
//! route. That boundary is recorded in ADR-0044.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::OutboundError;
use crate::node_dialer::{DialerOptions, NodeDialer, NodeServerDialer};

/// A configuration node pool with detour edges resolved on demand.
#[derive(Debug)]
pub struct NodeGraph<'a> {
    nodes: &'a [daer_config::Node],
    by_name: HashMap<&'a str, usize>,
    options: DialerOptions,
    cache: HashMap<usize, Arc<NodeDialer>>,
    stack: Vec<usize>,
}

impl<'a> NodeGraph<'a> {
    /// Builds the name index, rejecting duplicate names that would make a detour ambiguous.
    pub fn new(
        nodes: &'a [daer_config::Node],
        options: DialerOptions,
    ) -> Result<Self, OutboundError> {
        let mut by_name = HashMap::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            let Some(name) = node.name().map(str::trim).filter(|name| !name.is_empty()) else {
                continue;
            };
            if by_name.insert(name, index).is_some() {
                return Err(OutboundError::DuplicateNodeName(name.to_owned()));
            }
        }
        Ok(Self {
            nodes,
            by_name,
            options,
            cache: HashMap::new(),
            stack: Vec::new(),
        })
    }

    /// The node at `index`, with its detour chain assembled.
    pub fn build(&mut self, index: usize) -> Result<Arc<NodeDialer>, OutboundError> {
        if let Some(cached) = self.cache.get(&index) {
            return Ok(Arc::clone(cached));
        }
        if let Some(position) = self.stack.iter().position(|visited| *visited == index) {
            let mut chain: Vec<String> = self.stack[position..]
                .iter()
                .map(|visited| self.nodes[*visited].label())
                .collect();
            chain.push(self.nodes[index].label());
            return Err(OutboundError::DetourCycle(chain.join(" -> ")));
        }

        self.stack.push(index);
        let result = self.build_uncached(index);
        self.stack.pop();
        let dialer = Arc::new(result?);
        self.cache.insert(index, Arc::clone(&dialer));
        Ok(dialer)
    }

    /// Builds the node that declares `name`.
    pub fn build_named(&mut self, name: &str) -> Result<Arc<NodeDialer>, OutboundError> {
        let index =
            self.by_name
                .get(name)
                .copied()
                .ok_or_else(|| OutboundError::UnknownDetour {
                    node: name.to_owned(),
                    detour: name.to_owned(),
                })?;
        self.build(index)
    }

    /// The node's index, when a name names one.
    #[must_use]
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.by_name.get(name).copied()
    }

    fn build_uncached(&mut self, index: usize) -> Result<NodeDialer, OutboundError> {
        let node = self.nodes[index].clone();
        let Some(detour_name) = node.detour.as_deref().map(str::trim) else {
            return NodeDialer::from_node(&node, self.options.clone());
        };

        let target =
            self.by_name
                .get(detour_name)
                .copied()
                .ok_or_else(|| OutboundError::UnknownDetour {
                    node: node.label(),
                    detour: detour_name.to_owned(),
                })?;
        let inner = self.build(target).map_err(|error| match error {
            OutboundError::UnsupportedLink(reason) => OutboundError::DetourBroken {
                node: node.label(),
                detour: detour_name.to_owned(),
                reason,
            },
            other => other,
        })?;

        let options = self
            .options
            .clone()
            .with_base(Arc::new(NodeServerDialer::new(Arc::clone(&inner))));
        let dialer = NodeDialer::from_node(&node, options).map_err(|error| match error {
            OutboundError::UnsupportedLink(reason) => OutboundError::DetourBroken {
                node: node.label(),
                detour: detour_name.to_owned(),
                reason,
            },
            other => other,
        })?;
        Ok(dialer.with_detour(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daer_config::toml_config::load_str;

    fn config(text: &str) -> daer_config::Config {
        load_str(text).expect("config loads")
    }

    #[test]
    fn a_chain_is_built_once_and_shared() {
        let config = config(
            "schema = 6\n\
             [[node]]\nname = \"inner\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"inner\"\n",
        );
        let mut graph = NodeGraph::new(
            &config.node,
            DialerOptions::new(None, std::time::Duration::from_secs(1)),
        )
        .expect("graph");
        let outer = graph.build_named("outer").expect("builds outer");
        assert_eq!(outer.label(), "outer");
        assert_eq!(outer.detour().map(|node| node.label()), Some("inner"));
        let again = graph.build_named("outer").expect("cached");
        assert!(Arc::ptr_eq(&outer, &again));
    }

    #[test]
    fn an_unknown_detour_is_an_error() {
        let config = config(
            "schema = 6\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"missing\"\n",
        );
        let mut graph = NodeGraph::new(
            &config.node,
            DialerOptions::new(None, std::time::Duration::from_secs(1)),
        )
        .expect("graph");
        let error = graph.build_named("outer").expect_err("must fail");
        assert!(error.to_string().contains("missing"), "{error}");
    }

    #[test]
    fn a_cycle_is_rejected_even_if_the_validator_was_skipped() {
        let config = config(
            "schema = 6\n\
             [[node]]\nname = \"a\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\ndetour = \"b\"\n\
             [[node]]\nname = \"b\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"a\"\n",
        );
        let mut graph = NodeGraph::new(
            &config.node,
            DialerOptions::new(None, std::time::Duration::from_secs(1)),
        )
        .expect("graph");
        let error = graph.build_named("a").expect_err("must fail");
        assert!(error.to_string().contains("cycle"), "{error}");
    }

    /// A minimal SOCKS5 server that connects to the requested target and splices bytes.
    ///
    /// Returns the targets it was asked to connect to, so a test can prove which server saw
    /// which hop. This is deliberately not a mock of `NodeDialer`: the assertion is about the
    /// bytes on the wire, and the wire is where a chain either exists or does not.
    async fn socks5_forward(
        listener: tokio::net::TcpListener,
        seen: tokio::sync::mpsc::UnboundedSender<String>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_err() {
                    return None;
                }
                let mut methods = vec![0u8; greeting[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return None;
                }
                if stream.write_all(&[0x05, 0x00]).await.is_err() {
                    return None;
                }
                let mut head = [0u8; 4];
                if stream.read_exact(&mut head).await.is_err() {
                    return None;
                }
                let (host, port) = match head[3] {
                    0x01 => {
                        let mut addr = [0u8; 4];
                        stream.read_exact(&mut addr).await.ok()?;
                        let mut port = [0u8; 2];
                        stream.read_exact(&mut port).await.ok()?;
                        (
                            std::net::Ipv4Addr::from(addr).to_string(),
                            u16::from_be_bytes(port),
                        )
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.ok()?;
                        let mut host = vec![0u8; len[0] as usize];
                        stream.read_exact(&mut host).await.ok()?;
                        let mut port = [0u8; 2];
                        stream.read_exact(&mut port).await.ok()?;
                        (String::from_utf8(host).ok()?, u16::from_be_bytes(port))
                    }
                    0x04 => {
                        let mut addr = [0u8; 16];
                        stream.read_exact(&mut addr).await.ok()?;
                        let mut port = [0u8; 2];
                        stream.read_exact(&mut port).await.ok()?;
                        (
                            std::net::Ipv6Addr::from(addr).to_string(),
                            u16::from_be_bytes(port),
                        )
                    }
                    _ => return None,
                };
                let authority = format!("{host}:{port}");
                seen.send(authority.clone()).ok()?;
                let Ok(mut upstream) = tokio::net::TcpStream::connect(&authority).await else {
                    stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await
                        .ok();
                    return None;
                };
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                    .await
                    .ok();
                Option::<()>::None
            });
        }
    }

    #[tokio::test]
    async fn the_outer_protocol_runs_over_the_inner_outbound() {
        use tokio::net::TcpListener;
        use tokio::sync::mpsc;

        // The final origin, then two SOCKS5 servers. If the chain works, server B sees the
        // origin and server A sees B; if detour is ignored, A sees nothing.
        let origin = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("origin binds");
        let origin_addr = origin.local_addr().expect("origin addr");
        tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("origin accept");
            let mut payload = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .expect("origin read");
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
                .await
                .expect("origin write");
        });

        let server_b = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("B binds");
        let b_addr = server_b.local_addr().expect("B addr");
        let (b_seen, mut b_rx) = mpsc::unbounded_channel();
        tokio::spawn(socks5_forward(server_b, b_seen));

        let server_a = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("A binds");
        let a_addr = server_a.local_addr().expect("A addr");
        let (a_seen, mut a_rx) = mpsc::unbounded_channel();
        tokio::spawn(socks5_forward(server_a, a_seen));

        let inner =
            daer_config::Node::from_link(&format!("socks5://{a_addr}#inner")).expect("inner node");
        let mut outer =
            daer_config::Node::from_link(&format!("socks5://{b_addr}#outer")).expect("outer node");
        outer.detour = Some("inner".to_owned());
        let nodes = vec![inner, outer];

        let mut graph = NodeGraph::new(
            &nodes,
            DialerOptions::new(None, std::time::Duration::from_secs(2)),
        )
        .expect("graph");
        let dialer = graph.build_named("outer").expect("builds chain");

        let mut established = dialer
            .connect(&origin_addr.to_string())
            .await
            .expect("chain connects");
        tokio::io::AsyncWriteExt::write_all(&mut established.stream, b"hello")
            .await
            .expect("writes");
        let mut echoed = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut established.stream, &mut echoed)
            .await
            .expect("reads");
        assert_eq!(&echoed, b"hello");

        assert_eq!(
            a_rx.recv().await.as_deref(),
            Some(b_addr.to_string().as_str()),
            "the inner outbound must have been asked for the outer server, not the origin"
        );
        assert_eq!(
            b_rx.recv().await.as_deref(),
            Some(origin_addr.to_string().as_str()),
            "the outer protocol must still name the final target"
        );
    }

    #[tokio::test]
    async fn without_detour_the_inner_outbound_is_not_contacted() {
        use tokio::net::TcpListener;
        use tokio::sync::mpsc;

        let origin = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("origin binds");
        let origin_addr = origin.local_addr().expect("origin addr");
        tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("origin accept");
            let mut payload = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .expect("origin read");
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
                .await
                .expect("origin write");
        });

        let server_b = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("B binds");
        let b_addr = server_b.local_addr().expect("B addr");
        let (b_seen, _b_rx) = mpsc::unbounded_channel();
        tokio::spawn(socks5_forward(server_b, b_seen));

        let server_a = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("A binds");
        let a_addr = server_a.local_addr().expect("A addr");
        let (a_seen, mut a_rx) = mpsc::unbounded_channel();
        tokio::spawn(socks5_forward(server_a, a_seen));

        let inner =
            daer_config::Node::from_link(&format!("socks5://{a_addr}#inner")).expect("inner node");
        let outer =
            daer_config::Node::from_link(&format!("socks5://{b_addr}#outer")).expect("outer node");
        let nodes = vec![inner, outer];
        let mut graph = NodeGraph::new(
            &nodes,
            DialerOptions::new(None, std::time::Duration::from_secs(2)),
        )
        .expect("graph");
        let dialer = graph.build_named("outer").expect("builds outer");

        let mut established = dialer
            .connect(&origin_addr.to_string())
            .await
            .expect("direct outer connects");
        tokio::io::AsyncWriteExt::write_all(&mut established.stream, b"hello")
            .await
            .expect("writes");
        let mut echoed = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut established.stream, &mut echoed)
            .await
            .expect("reads");
        assert_eq!(&echoed, b"hello");
        assert!(
            a_rx.try_recv().is_err(),
            "the inner node must not be contacted without a detour"
        );
    }

    #[test]
    fn a_chain_can_be_arbitrarily_deep() {
        let config = config(
            "schema = 6\n\
             [[node]]\nname = \"c\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1082\n\
             [[node]]\nname = \"b\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"c\"\n\
             [[node]]\nname = \"a\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\ndetour = \"b\"\n",
        );
        let mut graph = NodeGraph::new(
            &config.node,
            DialerOptions::new(None, std::time::Duration::from_secs(1)),
        )
        .expect("graph");
        let a = graph.build_named("a").expect("builds");
        let b = a.detour().expect("b");
        let c = b.detour().expect("c");
        assert_eq!(b.label(), "b");
        assert_eq!(c.label(), "c");
        assert!(c.detour().is_none());
    }

    #[test]
    fn a_hysteria2_outer_hop_is_refused_with_the_reason() {
        let config = config(
            "schema = 6\n\
             [[node]]\nname = \"inner\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\
             [[node]]\nname = \"hy\"\ntype = \"hysteria2\"\nserver = \"127.0.0.1\"\nports = \"443\"\npassword = \"secret\"\ndetour = \"inner\"\n",
        );
        let mut graph = NodeGraph::new(
            &config.node,
            DialerOptions::new(None, std::time::Duration::from_secs(1)),
        )
        .expect("graph");
        let error = graph
            .build_named("hy")
            .expect_err("QUIC outer has no seam yet");
        assert!(error.to_string().contains("outer hop"), "{error}");
    }
}
