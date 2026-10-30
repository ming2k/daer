// SPDX-License-Identifier: AGPL-3.0-only

//! Reading until a name appears, without consuming the stream.
//!
//! # The constraint that shapes this module
//!
//! Sniffing happens **before** the routing decision, and the bytes inspected are also
//! the bytes the origin must eventually receive. So the reader cannot consume: it peeks.
//! `TcpStream::peek` returns bytes without advancing the reader, which makes the whole
//! operation observational — after a successful sniff the stream is exactly as the client
//! left it.
//!
//! ```text
//!   peek(8 KiB) ──▶ sniff ──Domain───▶ route by name, stream untouched
//!                    │
//!                    ├─NeedMore─▶ wait a little, peek again (bounded by the deadline)
//!                    ├─None─────▶ route by IP, stream untouched
//!                    └─Malformed▶ route by IP, record why
//! ```
//!
//! # Why a deadline and not a byte limit alone
//!
//! A client can open a connection and dribble one byte at a time, which no byte limit
//! stops. [`sniffing_timeout`] bounds the *whole* attempt: once it expires the flow is
//! routed by whatever is known, which is the IP. The byte budget
//! ([`MAX_SNIFF_LEN`]) bounds memory; the deadline bounds time. Both are needed, and
//! neither is optional.
//!
//! # Why the result is a value, not a side effect
//!
//! [`Outcome`] carries what was learned *and* why the attempt ended, so a caller can log
//! one line that answers "was this flow routed by domain, and if not, why not". A silent
//! fallback to IP would make a misconfigured rule indistinguishable from a client that
//! sent an indexable protocol.

use std::time::Duration;

use daer_sniff::{MAX_SNIFF_LEN, Protocol, Sniffed, sniff};
use tokio::net::TcpStream;

/// The most bytes peeked in one call.
///
/// Larger than [`MAX_SNIFF_LEN`] so a single peek usually sees a whole ClientHello rather
/// than looping: the syscall is the cost, not the buffer.
const PEEK_CHUNK: usize = 8192;

/// How long to wait between peeks when the prefix says "need more".
///
/// Short enough not to be the latency people notice, long enough not to spin. The
/// `sniffing-timeout` budget governs the total; this only paces the retries.
const RETRY_INTERVAL: Duration = Duration::from_millis(2);

/// What sniffing learned, and why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A name was recovered; route by it.
    Named {
        name: String,
        protocol: Protocol,
        /// How many bytes had to arrive before the name was complete.
        bytes: usize,
    },
    /// No name. Route by address.
    Unnamed(Unnamed),
}

impl Outcome {
    /// The name, when one was found.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Named { name, .. } => Some(name),
            Self::Unnamed(_) => None,
        }
    }

    /// True when the flow can be routed by domain.
    #[must_use]
    pub fn is_named(&self) -> bool {
        matches!(self, Self::Named { .. })
    }

    /// A one-line reason, for the flow log.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Named {
                name,
                protocol,
                bytes,
            } => format!("{protocol} sni={name} after {bytes}B"),
            Self::Unnamed(reason) => reason.to_string(),
        }
    }
}

/// Why no name was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unnamed {
    /// The bytes are not a protocol whose name can be recovered (QUIC, ECH, a
    /// non-indexable protocol, or plain bytes).
    NotSniffable,
    /// The bytes contradicted themselves: a length field overran the buffer.
    Malformed,
    /// The time budget expired before the name arrived.
    TimedOut,
    /// The peer closed before the name arrived.
    Closed,
    /// `peek` failed.
    Io,
    /// The name would not fit in the budget.
    TooLarge,
}

impl std::fmt::Display for Unnamed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotSniffable => "not a sniffable protocol; routing by address",
            Self::Malformed => "malformed prefix; routing by address",
            Self::TimedOut => "sniff timeout expired; routing by address",
            Self::Closed => "peer closed during sniffing; routing by address",
            Self::Io => "peek failed; routing by address",
            Self::TooLarge => "the name needed more than the sniff budget",
        })
    }
}

/// Peeks at `stream` until a name appears or the budget runs out.
///
/// The stream is **not** consumed; the caller forwards it as if this had not happened.
///
/// # Errors
///
/// Does not return an error: every failure mode is an [`Outcome::Unnamed`] with a reason,
/// because failing to sniff is a normal outcome (most flows start with something
/// unindexable) and not an error the caller must handle separately.
pub async fn sniff_stream(stream: &TcpStream, budget: Duration) -> Outcome {
    let deadline = tokio::time::Instant::now() + budget;
    let mut buffer = vec![0u8; PEEK_CHUNK];

    loop {
        // `peek` never advances the reader, so repeating it sees a growing prefix.
        let read = match tokio::time::timeout_at(deadline, stream.peek(&mut buffer)).await {
            Err(_) => return Outcome::Unnamed(Unnamed::TimedOut),
            Ok(Err(_)) => return Outcome::Unnamed(Unnamed::Io),
            Ok(Ok(0)) => return Outcome::Unnamed(Unnamed::Closed),
            Ok(Ok(read)) => read,
        };
        let available = &buffer[..read.min(MAX_SNIFF_LEN)];

        match sniff(available) {
            Sniffed::Domain { name, protocol } => {
                return Outcome::Named {
                    name,
                    protocol,
                    bytes: available.len(),
                };
            }
            Sniffed::None => return Outcome::Unnamed(Unnamed::NotSniffable),
            Sniffed::Malformed(_) => return Outcome::Unnamed(Unnamed::Malformed),
            Sniffed::NeedMore { want } => {
                // The suffix said more bytes would help. If it also said how many, and
                // that is past the budget, stop now rather than waiting for a deadline
                // that cannot help.
                if want.is_some_and(|want| want > MAX_SNIFF_LEN) {
                    return Outcome::Unnamed(Unnamed::TooLarge);
                }
                if available.len() >= MAX_SNIFF_LEN {
                    return Outcome::Unnamed(Unnamed::TooLarge);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Outcome::Unnamed(Unnamed::TimedOut);
                }
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// Whether a stream is worth peeking at all.
///
/// A flow whose first byte is already buffered is worth a sniff; one with nothing pending
/// costs a syscall and a wait. Exposed so a caller can skip the timer entirely when the
/// answer is already obvious — and so the decision is testable without sockets.
#[must_use]
pub fn is_worth_sniffing(first_byte: Option<u8>) -> bool {
    first_byte.is_some()
}

/// The peek buffer size, exposed for tests and for sizing the caller's own buffers.
#[must_use]
pub const fn peek_chunk() -> usize {
    PEEK_CHUNK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A connected pair: the returned stream is the "client" side of a local connection,
    /// which supports `peek` exactly like an accepted socket.
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        let client = TcpStream::connect(address).await.expect("connects");
        let (server, _) = listener.accept().await.expect("accepts");
        (client, server)
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

    #[tokio::test]
    async fn a_name_is_recovered_without_consuming_the_stream() {
        let (mut client, server) = pair().await;
        let hello = client_hello_with_sni("sniff.example.com");
        client.write_all(&hello).await.expect("writes");

        let outcome = sniff_stream(&server, Duration::from_secs(1)).await;
        match &outcome {
            Outcome::Named {
                name,
                protocol,
                bytes,
            } => {
                assert_eq!(name, "sniff.example.com");
                assert_eq!(*protocol, Protocol::Tls);
                assert_eq!(*bytes, hello.len());
            }
            other => panic!("expected a name, got {other:?}"),
        }

        // The bytes are still there: the origin must receive them unchanged.
        let mut received = vec![0u8; hello.len()];
        server
            .try_read(&mut received)
            .expect("reads what the client sent");
        assert_eq!(received, hello, "peeking must not consume");
    }

    #[tokio::test]
    async fn a_stream_that_never_sends_a_name_times_out() {
        // Nothing written at all: the deadline is the only thing that can end this.
        let (_client, server) = pair().await;
        let started = std::time::Instant::now();
        let outcome = sniff_stream(&server, Duration::from_millis(50)).await;
        assert_eq!(outcome, Outcome::Unnamed(Unnamed::TimedOut));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the budget must be honoured, not overshot"
        );
    }

    #[tokio::test]
    async fn a_non_sniffable_prefix_returns_immediately() {
        let (mut client, server) = pair().await;
        client
            .write_all(b"\x00\x01\x02\x03\x04\x05")
            .await
            .expect("writes");
        let outcome = sniff_stream(&server, Duration::from_secs(5)).await;
        assert_eq!(outcome, Outcome::Unnamed(Unnamed::NotSniffable));
    }

    #[tokio::test]
    async fn an_http_request_yields_its_host() {
        let (mut client, server) = pair().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n")
            .await
            .expect("writes");
        let outcome = sniff_stream(&server, Duration::from_secs(1)).await;
        assert_eq!(outcome.name(), Some("http.example.com"));
        // The exact byte count is whatever the peek returned; the name and protocol are
        // the contract.
        match outcome {
            Outcome::Named {
                name,
                protocol,
                bytes,
            } => {
                assert_eq!(name, "http.example.com");
                assert_eq!(protocol, Protocol::Http);
                assert_eq!(
                    bytes,
                    b"GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n".len()
                );
            }
            other => panic!("expected a name, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_closed_peer_is_reported_as_closed() {
        let (client, server) = pair().await;
        drop(client);
        let outcome = sniff_stream(&server, Duration::from_secs(1)).await;
        assert_eq!(outcome, Outcome::Unnamed(Unnamed::Closed));
    }

    #[test]
    fn every_unnamed_reason_renders_as_a_complete_sentence() {
        // These strings go straight into the flow log; a fragment would be unreadable.
        for reason in [
            Unnamed::NotSniffable,
            Unnamed::Malformed,
            Unnamed::TimedOut,
            Unnamed::Closed,
            Unnamed::Io,
            Unnamed::TooLarge,
        ] {
            let rendered = reason.to_string();
            assert!(
                rendered.contains("routing by address") || rendered.contains("sniff budget"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn an_outcome_describes_itself() {
        let named = Outcome::Named {
            name: "a.example".to_owned(),
            protocol: Protocol::Tls,
            bytes: 120,
        };
        assert!(named.is_named());
        assert_eq!(named.name(), Some("a.example"));
        assert_eq!(named.describe(), "tls sni=a.example after 120B");

        let unnamed = Outcome::Unnamed(Unnamed::TimedOut);
        assert!(!unnamed.is_named());
        assert_eq!(unnamed.name(), None);
        assert!(unnamed.describe().contains("timed out") || unnamed.describe().contains("timeout"));
    }

    #[test]
    fn sniffing_is_skipped_when_nothing_is_buffered() {
        assert!(is_worth_sniffing(Some(0x16)));
        assert!(!is_worth_sniffing(None));
        assert_eq!(peek_chunk(), PEEK_CHUNK);
    }
}
