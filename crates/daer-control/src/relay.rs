// SPDX-License-Identifier: AGPL-3.0-only

//! Byte relaying between the accepted flow and its outbound leg.
//!
//! # Half-close is the whole point
//!
//! A proxy must forward EOF, not connection teardown. A client that finishes its
//! request ([`AsyncWrite::shutdown`]) still expects the response, and a server
//! that finishes its response still expects the client to be able to write.
//! [`copy_bidirectional`] implements exactly that: when one direction reaches EOF
//! it shuts down the peer's write half and keeps the other direction running.
//! Writing this by hand is where proxies accumulate subtle hangs, so it is not
//! written by hand here.
//!
//! # Cancellation
//!
//! The relay holds no lock and awaits only on the two streams, so the caller
//! cancels it by dropping the future (structured concurrency). There is no
//! background task to leak and no shutdown flag to race with.

use std::io;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};

/// What a finished relay moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Relayed {
    /// Bytes read from the ingress side.
    pub to_upstream: u64,
    /// Bytes read from the upstream side.
    pub to_client: u64,
    /// Wall-clock time the relay was live.
    pub elapsed: Duration,
}

impl Relayed {
    /// Total bytes moved in both directions.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.to_upstream + self.to_client
    }

    /// Why the connection ended, as far as a proxy can tell: a relay that moved
    /// nothing is a probe or a failed dial, and is worth reporting differently
    /// from a closed session.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.to_upstream == 0 && self.to_client == 0
    }
}

/// Splices two halves until both directions have seen EOF.
///
/// # Errors
///
/// Returns the first I/O error from either direction. A half-close is not an
/// error: it is the normal way a direction ends.
pub async fn splice<C, U>(client: C, upstream: U) -> io::Result<Relayed>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let mut client = client;
    let mut upstream = upstream;
    // Tokio returns `(first_to_second, second_to_first)`; the names here are the
    // only place the direction convention appears, because swapping two `u64`s at
    // a call site would compile and be silently wrong.
    let (to_upstream, to_client) = copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(Relayed {
        to_upstream,
        to_client,
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn relays_in_both_directions() {
        let (client_side, client_relay) = duplex(64);
        let (upstream_side, upstream_relay) = duplex(64);

        let relay = tokio::spawn(splice(client_relay, upstream_relay));

        let mut client = client_side;
        let mut upstream = upstream_side;

        client.write_all(b"request").await.expect("writes");
        let mut buffer = [0u8; 7];
        upstream.read_exact(&mut buffer).await.expect("reads");
        assert_eq!(&buffer, b"request");

        upstream.write_all(b"response").await.expect("writes");
        let mut buffer = [0u8; 8];
        client.read_exact(&mut buffer).await.expect("reads");
        assert_eq!(&buffer, b"response");

        // Close the client's write half: the relay must forward EOF, and the
        // upstream must see it without losing the ability to keep writing.
        client.shutdown().await.expect("shutdown");
        let mut eof = [0u8; 1];
        assert_eq!(upstream.read(&mut eof).await.expect("reads eof"), 0);

        upstream.write_all(b"late").await.expect("still writable");
        let mut buffer = [0u8; 4];
        client.read_exact(&mut buffer).await.expect("reads");
        assert_eq!(&buffer, b"late");

        drop(client);
        drop(upstream);
        let relayed = relay.await.expect("joins").expect("relays");
        assert_eq!(relayed.to_upstream, 7);
        assert_eq!(relayed.to_client, 12);
        assert_eq!(relayed.total(), 19);
        assert!(!relayed.is_empty());
    }

    #[tokio::test]
    async fn dropping_the_relay_closes_both_halves() {
        let (client_side, client_relay) = duplex(16);
        let (upstream_side, upstream_relay) = duplex(16);

        let relay = tokio::spawn(splice(client_relay, upstream_relay));
        tokio::task::yield_now().await;
        relay.abort();
        let _ = relay.await;

        // Both ends observe a closed peer rather than hanging forever: the relay
        // owned the only handles to the two inner endpoints, and aborting it
        // dropped them.
        let mut client = client_side;
        let mut upstream = upstream_side;
        let mut buffer = [0u8; 8];
        assert!(matches!(client.read(&mut buffer).await, Ok(0) | Err(_)));
        assert!(matches!(upstream.read(&mut buffer).await, Ok(0) | Err(_)));
    }

    #[test]
    fn an_idle_relay_is_reported_as_empty() {
        assert!(Relayed::default().is_empty());
        assert_eq!(Relayed::default().total(), 0);
    }
}
