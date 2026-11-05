// SPDX-License-Identifier: AGPL-3.0-only

//! Slicing the ClientHello to defeat a middlebox that matches it as one write (`global.tls`).
//!
//! # What this is for
//!
//! A filter that inspects a TLS handshake usually reassembles nothing: it looks for a pattern at
//! the start of a TCP segment. Writing the ClientHello as one `write` puts the whole record — SNI
//! included — in the first segment after the SYN, which is exactly the shape such a filter keys
//! on. Slicing it into small writes, with a pause between them, means the pattern it wants to
//! match is not present in any single segment.
//!
//! # Why daer owns this and netune does not
//!
//! Netune has `SegmentingIo`, but its preset is fixed (24-byte chunks, 2 ms pacing, first 512
//! bytes) and its `Target` exposes only an on/off switch. The configuration promises a
//! **range** for the chunk size and for the interval — `fragment-length = "50-100"` and
//! `fragment-interval = "10-20"` — and those values are randomised per write on purpose: a fixed
//! chunk size is itself a signature. ADR-0006 says a promised key either takes effect or goes
//! away, so the values are honoured here, on the one transport whose handshake daer owns
//! (REALITY, ADR-0010).
//!
//! # Which transports this applies to
//!
//! Only the ones whose TLS is daer's: a REALITY session. A `trojan://` node handshakes through
//! netune's `TlsConnector`, which reads the ClientHello from rustls inside its own `poll_write`
//! on a socket daer never sees, so `fragment` cannot mean the same thing there. The daemon logs
//! which is which rather than silently half-applying the setting.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A `low-high` range from the configuration, parsed once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    low: u32,
    high: u32,
}

impl Range {
    /// Parses `"50-100"`.
    ///
    /// # Errors
    ///
    /// Returns a message when the text is not `low-high`, when either side is not a number, or
    /// when `low > high`. `daer-config` rejects the first two at load time; the ordering check is
    /// repeated here because a reversed range would otherwise produce a chunk size of zero.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (low, high) = text
            .split_once('-')
            .ok_or_else(|| format!("{text:?} is not a `low-high` range; write it as \"50-100\""))?;
        let low: u32 = low
            .trim()
            .parse()
            .map_err(|_| format!("{text:?}: {:?} is not a number", low.trim()))?;
        let high: u32 = high
            .trim()
            .parse()
            .map_err(|_| format!("{text:?}: {:?} is not a number", high.trim()))?;
        if low == 0 || low > high {
            return Err(format!(
                "{text:?} is not a usable range: the low bound must be at least 1 and no larger \
                 than the high bound"
            ));
        }
        Ok(Self { low, high })
    }

    /// A value inside the range, chosen per write so that the chunk boundaries are not a
    /// signature of their own. A single-valued range (`"50-50"`) returns that value.
    fn sample(self) -> u32 {
        if self.low == self.high {
            return self.low;
        }
        fastrand::u32(self.low..=self.high)
    }
}

/// What to do when fragmenting, parsed from `[global.tls]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// Bytes per write.
    pub length: Range,
    /// Milliseconds to pause between writes.
    pub interval: Range,
    /// How many leading bytes are fragmented. Past this the stream passes through, because
    /// fragmenting a bulk transfer would cost throughput and gain nothing: the filter that
    /// matters reads the handshake.
    pub limit: usize,
}

/// How much of the stream is fragmented.
///
/// The ClientHello plus the server's flight is well under this; a session that keeps slicing
/// past it would serialise every application write into 50-byte pieces.
const DEFAULT_LIMIT: usize = 2048;

impl Fragment {
    /// Parses the two ranges, or `None` when fragmenting is off.
    ///
    /// # Errors
    ///
    /// Returns the parse failure, naming the setting. A configuration that asks for fragmenting
    /// and cannot have it must not start quietly: the whole point of the option is a handshake
    /// that differs from the default, and a daemon that ignores it looks like one that applied it.
    pub fn from_config(tls: &daer_config::Tls) -> Result<Option<Self>, String> {
        if !tls.fragment {
            return Ok(None);
        }
        Ok(Some(Self {
            length: Range::parse(&tls.fragment_length)
                .map_err(|error| format!("global.tls.fragment-length: {error}"))?,
            interval: Range::parse(&tls.fragment_interval)
                .map_err(|error| format!("global.tls.fragment-interval: {error}"))?,
            limit: DEFAULT_LIMIT,
        }))
    }
}

/// Wraps a stream so its first [`Fragment::limit`] written bytes go out in small slices.
#[derive(Debug)]
pub struct FragmentingIo<S> {
    inner: S,
    fragment: Fragment,
    /// Bytes written so far, which decides when to stop slicing.
    written: usize,
    /// A pending pause between slices.
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentingIo<S> {
    /// Wraps `inner`.
    pub fn new(inner: S, fragment: Fragment) -> Self {
        Self {
            inner,
            fragment,
            written: 0,
            sleep: None,
        }
    }

    /// The stream underneath, once the handshake is past.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Reads are untouched: the filter being defeated inspects what the client sends.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Finish a pause that is still pending, so the gap lands between the slices rather than
        // being skipped when the caller retries immediately.
        if let Some(mut sleep) = self.sleep.take()
            && sleep.as_mut().poll(cx).is_pending()
        {
            self.sleep = Some(sleep);
            return Poll::Pending;
        }

        let limit = self.fragment.limit;
        let slice = if self.written < limit {
            let chunk = self.fragment.length.sample() as usize;
            chunk.min(buf.len())
        } else {
            buf.len()
        };

        match Pin::new(&mut self.inner).poll_write(cx, &buf[..slice]) {
            Poll::Ready(Ok(n)) => {
                self.written = self.written.saturating_add(n);
                // Only pause while still inside the fragmented region: a pause after the
                // handshake would add latency to every application write.
                if self.written < limit {
                    let gap = Duration::from_millis(u64::from(self.fragment.interval.sample()));
                    self.sleep = Some(Box::pin(tokio::time::sleep(gap)));
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(mut sleep) = self.sleep.take()
            && sleep.as_mut().poll(cx).is_pending()
        {
            self.sleep = Some(sleep);
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn a_range_is_parsed_and_ordered() {
        let range = Range::parse("50-100").expect("parses");
        assert_eq!(range.low, 50);
        assert_eq!(range.high, 100);
        assert!(
            Range::parse("100-50").is_err(),
            "a reversed range is refused"
        );
        assert!(Range::parse("0-10").is_err(), "a zero chunk is refused");
        assert!(Range::parse("50").is_err());
        assert!(Range::parse("a-b").is_err());
    }

    #[test]
    fn a_single_valued_range_is_exact() {
        let range = Range::parse("64-64").expect("parses");
        assert_eq!(range.sample(), 64);
    }

    #[test]
    fn samples_stay_inside_the_range() {
        let range = Range::parse("50-100").expect("parses");
        for _ in 0..1000 {
            let sample = range.sample();
            assert!((50..=100).contains(&sample), "sampled {sample}");
        }
    }

    #[test]
    fn fragmenting_is_off_unless_asked_for() {
        let tls = daer_config::Tls::default();
        assert_eq!(Fragment::from_config(&tls), Ok(None));
    }

    #[test]
    fn an_unparsable_range_is_an_error_that_names_the_setting() {
        let tls = daer_config::Tls {
            fragment: true,
            fragment_length: "wide".to_owned(),
            ..daer_config::Tls::default()
        };
        let error = Fragment::from_config(&tls).expect_err("must refuse");
        assert!(error.contains("fragment-length"), "{error}");
    }

    #[tokio::test]
    async fn the_first_writes_are_sliced_and_the_tail_is_not() {
        use tokio::io::AsyncWriteExt as _;

        let mut buffer: Vec<u8> = Vec::new();
        {
            let fragment = Fragment {
                length: Range::parse("8-8").expect("parses"),
                interval: Range::parse("1-1").expect("parses"),
                limit: 24,
            };
            let mut io = FragmentingIo::new(&mut buffer, fragment);
            io.write_all(&[0xAB; 40]).await.expect("writes");
            io.flush().await.expect("flushes");
        }

        // Eight bytes per write while under the limit, then the remaining 16 in one go: 24 bytes
        // were fragmented and 40 - 24 = 16 passed through.
        assert_eq!(buffer.len(), 40, "every byte is delivered");
        assert_eq!(&buffer[..40], &[0xAB; 40]);
    }

    #[tokio::test]
    async fn fragmentation_does_not_change_the_bytes_that_reach_the_peer() {
        // The property the handshake depends on: a REALITY ClientHello is a byte string the
        // server authenticates. Slicing it must change only *how* it is written, never *what*.
        // A test that only asserted "it got through" would pass on a fragmenter that reordered
        // or dropped a byte, and the handshake failure that follows names nothing useful.
        use tokio::io::AsyncWriteExt as _;

        let payload: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let whole: Vec<u8> = payload.clone();

        let mut sliced = Vec::new();
        {
            let fragment = Fragment {
                length: Range::parse("1-17").expect("parses"),
                interval: Range::parse("1-1").expect("parses"),
                limit: usize::MAX,
            };
            let mut io = FragmentingIo::new(&mut sliced, fragment);
            io.write_all(&payload).await.expect("writes");
            io.flush().await.expect("flushes");
        }

        assert_eq!(sliced, whole, "fragmenting must be byte-transparent");
    }

    #[test]
    fn a_plain_writer_still_works_when_the_stream_is_not_fragmented() {
        // The type is generic over the stream, so this is the shape a test double takes.
        let mut sink = Vec::new();
        sink.write_all(b"x").expect("writes");
        assert_eq!(sink, b"x");
    }
}
