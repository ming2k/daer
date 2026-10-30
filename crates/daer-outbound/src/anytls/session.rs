// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS multiplexed session coordinator.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::anytls::frame::{Command, Frame};
use crate::anytls::stream::AnyTlsStream;
use crate::error::OutboundError;
use crate::shadowsocks::connector::split_authority;

/// Default timeout waiting for a server SYNACK response.
const SYNACK_TIMEOUT: Duration = Duration::from_secs(10);

type SynAckMap = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<(), String>>>>>;
type StreamMap = Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>;

/// A long-lived AnyTLS multiplexed session over a single TLS connection.
pub struct AnyTlsSession {
    next_stream_id: AtomicU32,
    pending_synacks: SynAckMap,
    active_streams: StreamMap,
    outbound_tx: mpsc::UnboundedSender<Frame>,
    is_closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for AnyTlsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsSession")
            .field(
                "next_stream_id",
                &self.next_stream_id.load(Ordering::Relaxed),
            )
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

impl AnyTlsSession {
    /// Spawns background reader, writer, and heartbeat tasks for an established TLS transport.
    pub fn new(transport: Box<dyn netune::Transport>) -> Arc<Self> {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let pending_synacks = Arc::new(Mutex::new(HashMap::new()));
        let active_streams = Arc::new(Mutex::new(HashMap::new()));
        let is_closed = Arc::new(AtomicBool::new(false));

        let session = Arc::new(Self {
            next_stream_id: AtomicU32::new(1),
            pending_synacks: Arc::clone(&pending_synacks),
            active_streams: Arc::clone(&active_streams),
            outbound_tx: outbound_tx.clone(),
            is_closed: Arc::clone(&is_closed),
        });

        let (reader, writer) = tokio::io::split(transport);

        // Spawn reader loop
        let reader_synacks = Arc::clone(&pending_synacks);
        let reader_streams = Arc::clone(&active_streams);
        let reader_closed = Arc::clone(&is_closed);
        let reader_tx = outbound_tx.clone();
        tokio::spawn(async move {
            Self::reader_loop(
                reader,
                reader_synacks,
                reader_streams,
                reader_closed,
                reader_tx,
            )
            .await;
        });

        // Spawn writer loop
        let writer_closed = Arc::clone(&is_closed);
        tokio::spawn(async move {
            Self::writer_loop(writer, outbound_rx, writer_closed).await;
        });

        // Spawn periodic heartbeat
        let hb_tx = outbound_tx;
        let hb_closed = Arc::clone(&is_closed);
        tokio::spawn(async move {
            Self::heartbeat_loop(hb_tx, hb_closed).await;
        });

        session
    }

    /// Whether this session has been closed or experienced an unrecoverable error.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::SeqCst)
    }

    /// Opens a virtual stream to the requested destination (`host:port`).
    pub async fn open_stream(&self, authority: &str) -> Result<AnyTlsStream, OutboundError> {
        if self.is_closed() {
            return Err(OutboundError::Connect(
                "anytls session is closed".to_owned(),
            ));
        }

        let (host, port) = split_authority(authority).map_err(OutboundError::UnsupportedLink)?;
        let dest_addr_bytes = crate::shadowsocks::connector::encode_address(host, port)
            .map_err(OutboundError::UnsupportedLink)?;

        // Allocate client stream ID (odd number)
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);

        let (synack_tx, synack_rx) = oneshot::channel();
        {
            let mut pending = self
                .pending_synacks
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.insert(stream_id, synack_tx);
        }

        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        {
            let mut streams = self
                .active_streams
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            streams.insert(stream_id, inbound_tx);
        }

        // Send Syn frame
        if self.outbound_tx.send(Frame::syn(stream_id)).is_err() {
            self.cleanup_stream(stream_id);
            return Err(OutboundError::Connect(
                "anytls session writer closed".to_owned(),
            ));
        }

        // Send SOCKS5 destination address as initial payload
        if self
            .outbound_tx
            .send(Frame::push(stream_id, Bytes::from(dest_addr_bytes)))
            .is_err()
        {
            self.cleanup_stream(stream_id);
            return Err(OutboundError::Connect(
                "anytls session writer closed".to_owned(),
            ));
        }

        // Wait for server SYNACK
        match tokio::time::timeout(SYNACK_TIMEOUT, synack_rx).await {
            Ok(Ok(Ok(()))) => Ok(AnyTlsStream::new(
                stream_id,
                inbound_rx,
                self.outbound_tx.clone(),
            )),
            Ok(Ok(Err(err_msg))) => {
                self.cleanup_stream(stream_id);
                Err(OutboundError::Connect(format!(
                    "anytls server rejected stream {stream_id}: {err_msg}"
                )))
            }
            Ok(Err(_)) => {
                self.cleanup_stream(stream_id);
                Err(OutboundError::Connect(
                    "anytls session dropped pending synack".to_owned(),
                ))
            }
            Err(_) => {
                self.cleanup_stream(stream_id);
                Err(OutboundError::Timeout)
            }
        }
    }

    fn cleanup_stream(&self, stream_id: u32) {
        let mut pending = self
            .pending_synacks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.remove(&stream_id);
        let mut streams = self
            .active_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        streams.remove(&stream_id);
    }

    async fn reader_loop<R: tokio::io::AsyncRead + Unpin>(
        mut reader: R,
        pending_synacks: SynAckMap,
        active_streams: StreamMap,
        is_closed: Arc<AtomicBool>,
        outbound_tx: mpsc::UnboundedSender<Frame>,
    ) {
        let mut buf = BytesMut::with_capacity(32 * 1024);

        loop {
            // Attempt to parse completed frames
            while let Ok(Some(frame)) = Frame::decode(&mut buf) {
                match frame.cmd {
                    Command::SynAck => {
                        let sender = {
                            let mut pending =
                                pending_synacks.lock().unwrap_or_else(|e| e.into_inner());
                            pending.remove(&frame.stream_id)
                        };
                        if let Some(tx) = sender {
                            let result = if frame.data.is_empty() {
                                Ok(())
                            } else {
                                Err(String::from_utf8_lossy(&frame.data).to_string())
                            };
                            let _ = tx.send(result);
                        }
                    }
                    Command::Push => {
                        let stream_sender = {
                            let streams = active_streams.lock().unwrap_or_else(|e| e.into_inner());
                            streams.get(&frame.stream_id).cloned()
                        };
                        if let Some(tx) = stream_sender
                            && tx.send(frame.data).await.is_err()
                        {
                            // Stream consumer dropped, clean up and send FIN
                            let mut streams =
                                active_streams.lock().unwrap_or_else(|e| e.into_inner());
                            streams.remove(&frame.stream_id);
                            let _ = outbound_tx.send(Frame::fin(frame.stream_id));
                        }
                    }
                    Command::Fin => {
                        let mut streams = active_streams.lock().unwrap_or_else(|e| e.into_inner());
                        streams.remove(&frame.stream_id);
                    }
                    Command::HeartRequest => {
                        let _ = outbound_tx.send(Frame::heart_response());
                    }
                    Command::HeartResponse => {
                        // Heartbeat reply received
                    }
                    Command::Waste
                    | Command::Settings
                    | Command::UpdatePaddingScheme
                    | Command::ServerSettings => {
                        // Padding or settings frames are discarded
                    }
                    Command::Alert => {
                        let alert_msg = String::from_utf8_lossy(&frame.data);
                        tracing::warn!(alert = %alert_msg, "anytls received alert from server");
                        break;
                    }
                    Command::Syn | Command::Unknown(_) => {
                        // Unused in client receiver
                    }
                }
            }

            match reader.read_buf(&mut buf).await {
                Ok(0) => {
                    // EOF from peer
                    break;
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::debug!(error = %err, "anytls session read error");
                    break;
                }
            }
        }

        // Mark closed and notify remaining waiters
        is_closed.store(true, Ordering::SeqCst);
        let mut pending = pending_synacks.lock().unwrap_or_else(|e| e.into_inner());
        for (_, tx) in pending.drain() {
            let _ = tx.send(Err("anytls session closed unexpectedly".to_owned()));
        }
        let mut streams = active_streams.lock().unwrap_or_else(|e| e.into_inner());
        streams.clear();
    }

    async fn writer_loop<W: tokio::io::AsyncWrite + Unpin>(
        mut writer: W,
        mut outbound_rx: mpsc::UnboundedReceiver<Frame>,
        is_closed: Arc<AtomicBool>,
    ) {
        let mut write_buf = Vec::with_capacity(32 * 1024);

        while let Some(frame) = outbound_rx.recv().await {
            write_buf.clear();
            frame.encode_buf(&mut write_buf);

            // Coalesce additional ready frames if available in channel
            while let Ok(next) = outbound_rx.try_recv() {
                next.encode_buf(&mut write_buf);
                if write_buf.len() > 64 * 1024 {
                    break;
                }
            }

            if let Err(err) = writer.write_all(&write_buf).await {
                tracing::debug!(error = %err, "anytls session write error");
                break;
            }
            if let Err(err) = writer.flush().await {
                tracing::debug!(error = %err, "anytls session flush error");
                break;
            }
        }

        is_closed.store(true, Ordering::SeqCst);
    }

    async fn heartbeat_loop(outbound_tx: mpsc::UnboundedSender<Frame>, is_closed: Arc<AtomicBool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        // First tick completes immediately
        interval.tick().await;

        while !is_closed.load(Ordering::SeqCst) {
            interval.tick().await;
            if outbound_tx.send(Frame::heart_request()).is_err() {
                break;
            }
        }
    }
}
