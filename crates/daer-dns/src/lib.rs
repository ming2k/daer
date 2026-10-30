// SPDX-License-Identifier: AGPL-3.0-only

//! DNS for daer: wire format, request/response routing, cache, upstream transports.
//!
//! # Scope
//!
//! The *server* role is this crate's, not netune's: netune supplies a client resolver
//! for its own dialing, while a transparent proxy has to answer queries from arbitrary
//! clients and decide, per query, which upstream to ask and what to do with the answer.
//! See `docs/adr/0002-netune-boundary.md`.
//!
//! | Part | State |
//! | --- | --- |
//! | [`wire`] — parse/encode, names, records, compression | done |
//! | [`routing`] — `[dns.request]` / `[dns.response]` evaluation | done |
//! | [`cache`] — bounded, TTL-aware, stale-while-revalidate | done |
//! | [`resolver`] — the pipeline: routing → cache → transport → response routing | done |
//! | [`transport`] — `dns.upstream` syntax, DNS over TCP | done (UDP/DoT/DoH need netune) |
//! | [`server`] — UDP and TCP server sockets | done |
//! | bootstrap resolver | not started |
//!
//! # Why the wire format is owned
//!
//! A resolver here needs to read a question and rewrite a TTL, not to be a full DNS
//! stack. See [`wire`] for what is deliberately absent and why a small owned parser is
//! preferable to pulling in a library whose executed surface would be larger than the
//! part used.
//!
//! # Example
//!
//! ```
//! use daer_dns::{Decision, Name, Question, RecordType, RequestRouter, wire};
//!
//! let config = daer_config::toml_config::load_str(
//!     r#"
//! [dns]
//! upstream = ["local:udp://223.5.5.5:53"]
//!
//! [dns.request]
//! rules = ["qname(suffix: ads) -> reject"]
//! fallback = "local"
//! "#,
//! )
//! .expect("config loads");
//!
//! let router = RequestRouter::compile(&config).expect("compiles");
//! let query = wire::Message {
//!     id: 42,
//!     flags: wire::Flags(0x0100),
//!     questions: vec![Question::internet(
//!         Name::parse("tracker.ads").expect("name"),
//!         RecordType::A,
//!     )],
//!     answers: Vec::new(),
//!     authorities: Vec::new(),
//!     additionals: Vec::new(),
//! };
//!
//! assert_eq!(router.decide(&query), Decision::Reject);
//! // The same query survives a round trip through the wire format.
//! let decoded = wire::parse(&wire::encode(&query)).expect("parses");
//! assert_eq!(router.decide(&decoded), Decision::Reject);
//! ```

pub mod cache;
pub mod resolver;
pub mod routing;
pub mod server;
pub mod transport;
pub mod wire;

pub use cache::{Cache, CacheConfig, Cached, Key, Skipped};
pub use resolver::{
    ExchangeFuture, Resolution, Resolver, ResolverError, Stats, StatsSnapshot, Upstream,
    UpstreamError,
};
pub use routing::{
    AnswerFacts, Decision, RequestRouter, ResponseAction, ResponseRouter, RoutingError,
    upstream_tags,
};
pub use server::{
    ServerError, UDP_MAX_LIMIT, UDP_PLAIN_LIMIT, encode_datagram, serve_tcp, serve_tcp_on,
    serve_udp, serve_udp_on, udp_payload_limit,
};
pub use transport::{
    ChainUpstream, DEFAULT_DOH_PATH, HttpsUpstream, Protocol, TcpUpstream, TlsUpstream,
    UdpUpstream, UpstreamSpec, is_truncated,
};
pub use wire::{
    Flags, Message, Name, ParseError, Question, Record, RecordType, ResponseCode, encode, parse,
};
