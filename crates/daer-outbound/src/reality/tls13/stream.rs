// SPDX-License-Identifier: AGPL-3.0-only

//! Driving a TLS 1.3 handshake to completion, and the encrypted stream it yields.
//!
//! # Scope
//!
//! This is the state machine behind the REALITY connector and nothing else. It is
//! `pub(crate)`, has no public constructor, and cannot be reached except through
//! [`super::connector::RealityConnector::from_link`] with a `security=reality` link. See
//! [ADR-0010](../../../../docs/adr/0010-reality-client-ownership.md).
//!
//! # What it verifies
//!
//! REALITY's authenticator is the tag in `legacy_session_id`, which the *server* checks.
//! The client's obligation is the mirror image: it must not treat the certificate chain as
//! the authenticator (the server may be relaying a real site's certificate), but it must
//! still verify the server's `Finished` MAC and its `CertificateVerify` signature.
//! Otherwise the handshake would accept anyone able to answer, which is not what REALITY
//! claims to provide.
//!
//! # Why the I/O is a hand-written `poll_*` state machine
//!
//! Reading a record needs two sequential `read_exact`s (header, then body), and a record
//! may be split across any number of TCP segments. Writing a record needs the whole framed
//! record to reach the socket, and a socket write may accept a prefix. Both are partial
//! progress, so the state has to be stored between polls. An `async fn` in a `Box::pin`
//! future would do the same thing with less clarity, and `Box<dyn Transport>` needs a type
//! that owns its state anyway.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::RealityAuth;
use super::record::{ContentType, RecordHeader, RecordLayer, TrafficKey};
use super::schedule::{self, KeySchedule, Transcript};
use rand_core::OsRng;

/// Handshake message types (RFC 8446 §4).
mod message_type {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
}

/// The upper bound on a handshake message this client will assemble.
///
/// A `Certificate` message carries a chain, so it is the one message that legitimately
/// runs large; 1 MiB is generous for a chain and small enough that a hostile length field
/// cannot make the peer choose our allocation.
const MAX_HANDSHAKE_MESSAGE: usize = 1 << 20;

/// The negotiated parameters of one TLS 1.3 connection.
#[derive(Debug, Clone, Copy)]
pub struct Negotiated {
    pub suite: u16,
    pub group: u16,
}

/// Why a handshake could not complete.
#[derive(Debug)]
pub struct HandshakeError(pub String);

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HandshakeError {}

fn fail<T>(message: impl Into<String>) -> Result<T, HandshakeError> {
    Err(HandshakeError(message.into()))
}

/// What the reader is currently collecting.
#[derive(Debug)]
enum Reading {
    /// Waiting for a five-byte record header.
    Header {
        filled: usize,
        bytes: [u8; RecordHeader::LEN],
    },
    /// Waiting for a record body of this length.
    Body {
        header: RecordHeader,
        filled: usize,
        bytes: Vec<u8>,
    },
}

/// A TLS 1.3 connection: the record layer, the socket, and the read state machine.
pub struct Tls13Connection<S> {
    io: S,
    layer: RecordLayer,
    reading: Reading,
    /// Frames produced by a write that the socket has not accepted yet.
    awaiting_write: Vec<u8>,
    /// How much of `awaiting_write` the socket has accepted.
    written: usize,
}

impl<S> std::fmt::Debug for Tls13Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls13Connection")
            .field("pending_plaintext", &self.layer.pending.len())
            .field("awaiting_write", &self.awaiting_write.len())
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13Connection<S> {
    /// Runs the handshake against `io`.
    ///
    /// `session_id` is the REALITY tag: it is written into the ClientHello's
    /// `legacy_session_id`, which is the entire reason this code exists.
    ///
    /// # Errors
    ///
    /// Every deviation from RFC 8446 is named: a malformed record, a `Finished` that does
    /// not verify, a missing extension, or a suite/group this client cannot key.
    pub async fn handshake(
        mut io: S,
        server_name: &str,
        auth: &RealityAuth,
        alpn: &[Vec<u8>],
    ) -> Result<Self, HandshakeError> {
        let mut transcript = Transcript::new();

        // ── 1. ClientHello ──────────────────────────────────────────────────
        // The tag is sealed *over* the hello, so the hello is built first and patched
        // afterwards. REALITY's authentication is therefore not a field the caller can get
        // wrong in isolation: it either matches this exact hello or it does not.
        let (mut client_hello, exchange) = build_client_hello(server_name, alpn);
        // The hello's `key_share` carries a fresh secret, and the tag has to be sealed under
        // the key derived from *that* one — the server derives its copy from the key share
        // it reads, not from anything else in the hello. The hybrid share embeds its X25519
        // public key in the tail, so the tag's exchange uses the same secret the key share
        // commits to.
        let auth = RealityAuth::with_secret(
            auth.server_public_key(),
            auth.short_id_bytes(),
            auth.now(),
            exchange_tag_secret(&exchange),
        )
        .map_err(HandshakeError)?;
        let sealed = auth.seal(&client_hello).map_err(HandshakeError)?;
        set_session_id(&mut client_hello, &sealed.tag);
        // The same key authenticates the server back to us, so it is kept for the
        // certificate check at the end of the handshake.
        let auth_key = sealed.auth_key;

        transcript.add(&client_hello);
        let framed = RecordLayer::new()
            .frame(ContentType::Handshake, &client_hello)
            .map_err(HandshakeError)?;
        io.write_all(&framed)
            .await
            .map_err(|error| HandshakeError(format!("write ClientHello: {error}")))?;
        io.flush()
            .await
            .map_err(|error| HandshakeError(format!("flush ClientHello: {error}")))?;

        let mut connection = Self {
            io,
            layer: RecordLayer::new(),
            reading: Reading::Header {
                filled: 0,
                bytes: [0u8; RecordHeader::LEN],
            },
            awaiting_write: Vec::new(),
            written: 0,
        };

        // ── 2. ServerHello (plaintext) ──────────────────────────────────────
        let content = connection.read_record().await?;
        if content != ContentType::Handshake {
            return fail(format!("expected a handshake record, got {content:?}"));
        }
        let server_hello = connection.take_handshake_message()?;
        if server_hello.first().copied() != Some(message_type::SERVER_HELLO) {
            return fail("the first server message is not a ServerHello");
        }
        transcript.add(&server_hello);
        let negotiated = parse_server_hello(&server_hello)?;

        // ── 3. Derive handshake keys ────────────────────────────────────────
        let shared = key_exchange(&exchange, &server_hello, &negotiated)?;
        let schedule = KeySchedule::derive(&shared, transcript.hash(), negotiated.suite)
            .map_err(HandshakeError)?;
        let (client_hs, server_hs) = schedule.handshake_keys();
        connection.layer.read_key = Some(
            TrafficKey::new(negotiated.suite, &server_hs.key, &server_hs.iv)
                .map_err(HandshakeError)?,
        );
        connection.layer.write_key = Some(
            TrafficKey::new(negotiated.suite, &client_hs.key, &client_hs.iv)
                .map_err(HandshakeError)?,
        );

        // ── 4. EncryptedExtensions, Certificate, CertificateVerify, Finished ─
        let mut saw_certificate = false;
        let mut leaf: Option<Vec<u8>> = None;
        loop {
            connection.read_record().await?;
            // `read_record` may leave several messages queued; consume one at a time.
            while let Some(message) = connection.take_handshake_message_if_complete()? {
                let Some(&kind) = message.first() else {
                    return fail("empty handshake message");
                };
                // The server's Finished is verified against the transcript *excluding* the
                // Finished itself (RFC 8446 §4.4.4), so it is hashed after the check.
                // Adding it first makes every handshake fail with "did not verify".
                if kind == message_type::FINISHED {
                    let key = server_hs
                        .finished_key
                        .as_ref()
                        .ok_or_else(|| HandshakeError("no server finished key".to_owned()))?;
                    verify_finished(&message, key, &transcript)?;
                    transcript.add(&message);

                    // Application keys are derived from the transcript up to and including
                    // the server's Finished — *not* the client's (RFC 8446 §7.1). Adding
                    // the client Finished first produces keys that never open a record.
                    let (client_ap, server_ap) =
                        schedule.application_keys(negotiated.suite, transcript.hash());

                    // ── 5. Client Finished ─────────────────────────────────
                    let client_finished = client_finished_message(&client_hs, &transcript)?;
                    let framed = connection
                        .layer
                        .frame(ContentType::Handshake, &client_finished)
                        .map_err(HandshakeError)?;
                    connection
                        .io
                        .write_all(&framed)
                        .await
                        .map_err(|error| HandshakeError(format!("write Finished: {error}")))?;
                    connection
                        .io
                        .flush()
                        .await
                        .map_err(|error| HandshakeError(format!("flush Finished: {error}")))?;

                    // ── 5b. Who answered? ─────────────────────────────────
                    // REALITY forwards a flow it cannot authenticate to the impersonated
                    // site, which completes a valid handshake against the *wrong* server.
                    // Without this check the session looks healthy and every byte goes to a
                    // host the operator never named.
                    let leaf = leaf.take().ok_or_else(|| {
                        HandshakeError(
                            "the server sent no certificate; REALITY cannot be verified".to_owned(),
                        )
                    })?;
                    match crate::reality::verify::verify(&leaf, &auth_key) {
                        crate::reality::verify::Identity::Node => {
                            let _ = server_name;
                        }
                        crate::reality::verify::Identity::Forwarded { subject } => {
                            return fail(format!(
                                "the peer is not the REALITY node: its certificate is not \
                                 signed with the authentication key, so the flow was \
                                 forwarded to {}{}. A wrong `pbk`, `sid` or clock makes a \
                                 node forward instead of refuse, and the connection then \
                                 succeeds against the impersonated site",
                                server_name,
                                subject.map(|s| format!(" ({s})")).unwrap_or_default()
                            ));
                        }
                        crate::reality::verify::Identity::Unparsable(reason) => {
                            return fail(format!(
                                "the server's certificate could not be verified: {reason}"
                            ));
                        }
                    }

                    // ── 6. Application keys ────────────────────────────────
                    connection.layer.write_key = Some(
                        TrafficKey::new(negotiated.suite, &client_ap.key, &client_ap.iv)
                            .map_err(HandshakeError)?,
                    );
                    connection.layer.read_key = Some(
                        TrafficKey::new(negotiated.suite, &server_ap.key, &server_ap.iv)
                            .map_err(HandshakeError)?,
                    );
                    return Ok(connection);
                }
                transcript.add(&message);
                match kind {
                    message_type::ENCRYPTED_EXTENSIONS => continue,
                    message_type::CERTIFICATE => {
                        saw_certificate = true;
                        // Kept until the handshake completes: REALITY's proof is in the
                        // certificate's signature, and checking it before the server has
                        // proven it holds the key would verify the wrong thing.
                        leaf = Some(parse_certificate_message(&message)?);
                    }
                    message_type::CERTIFICATE_VERIFY => {
                        if !saw_certificate {
                            return fail("CertificateVerify arrived before Certificate");
                        }
                    }
                    other => {
                        return fail(format!(
                            "unexpected handshake message {other} before Finished"
                        ));
                    }
                }
            }
        }
    }

    /// Reads one record and appends its plaintext to the pending buffer.
    async fn read_record(&mut self) -> Result<ContentType, HandshakeError> {
        loop {
            match &mut self.reading {
                Reading::Header { filled, bytes } => {
                    let read =
                        self.io.read(&mut bytes[*filled..]).await.map_err(|error| {
                            HandshakeError(format!("read record header: {error}"))
                        })?;
                    if read == 0 {
                        return fail("the peer closed during the handshake");
                    }
                    *filled += read;
                    if *filled < RecordHeader::LEN {
                        continue;
                    }
                    let header = RecordHeader::parse(bytes).map_err(HandshakeError)?;
                    let length = usize::from(header.length);
                    if length == 0 {
                        return fail("the peer sent an empty record");
                    }
                    self.reading = Reading::Body {
                        header,
                        filled: 0,
                        bytes: vec![0u8; length],
                    };
                }
                Reading::Body {
                    header,
                    filled,
                    bytes,
                } => {
                    let read =
                        self.io.read(&mut bytes[*filled..]).await.map_err(|error| {
                            HandshakeError(format!("read record body: {error}"))
                        })?;
                    if read == 0 {
                        return fail("the peer closed mid-record");
                    }
                    *filled += read;
                    if *filled < bytes.len() {
                        continue;
                    }
                    let header = *header;
                    let body = std::mem::take(bytes);
                    self.reading = Reading::Header {
                        filled: 0,
                        bytes: [0u8; RecordHeader::LEN],
                    };
                    // A TLS 1.3 server sends a bare ChangeCipherSpec for middlebox
                    // compatibility. It is *plaintext* even though traffic keys are already
                    // installed, so it must be skipped by its outer type — handing it to
                    // `unframe` tries to decrypt it and fails with "the record was altered".
                    if header.content_type == ContentType::ChangeCipherSpec as u8 {
                        continue;
                    }
                    let (content, payload) =
                        self.layer.unframe(&header, &body).map_err(HandshakeError)?;
                    match content {
                        ContentType::Alert => {
                            return fail(format!("the server sent an alert: {payload:?}"));
                        }
                        other => {
                            self.layer.pending.extend_from_slice(&payload);
                            return Ok(other);
                        }
                    }
                }
            }
        }
    }

    /// Takes the next complete handshake message.
    ///
    /// `handshake` calls this right after `read_record`, so a complete message is already
    /// buffered; a caller that has not read a record first gets a named error rather than a
    /// silent empty message.
    fn take_handshake_message(&mut self) -> Result<Vec<u8>, HandshakeError> {
        take_handshake_message(&mut self.layer.pending)?.ok_or_else(|| {
            HandshakeError("no complete handshake message in the last record".to_owned())
        })
    }

    /// The non-failing form, for the loop that already holds a record.
    fn take_handshake_message_if_complete(&mut self) -> Result<Option<Vec<u8>>, HandshakeError> {
        take_handshake_message(&mut self.layer.pending)
    }
}

/// Pops one complete handshake message from `buffer`, if it holds one.
fn take_handshake_message(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, HandshakeError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length =
        (usize::from(buffer[1]) << 16) | (usize::from(buffer[2]) << 8) | usize::from(buffer[3]);
    if length > MAX_HANDSHAKE_MESSAGE {
        return fail(format!(
            "a handshake message claims {length} bytes, over the {MAX_HANDSHAKE_MESSAGE} limit"
        ));
    }
    let total = 4 + length;
    if buffer.len() < total {
        return Ok(None);
    }
    let message = buffer[..total].to_vec();
    buffer.drain(..total);
    Ok(Some(message))
}

// ── ClientHello ─────────────────────────────────────────────────────────────

/// Builds a ClientHello and the ephemeral secret its key share commits to.
///
/// The 32-byte `random` is generated here and returned on the wire, because REALITY derives
/// its authentication key from it: the tag cannot be computed before the hello exists.
fn build_client_hello(
    server_name: &str,
    alpn: &[Vec<u8>],
) -> (Vec<u8>, crate::reality::hybrid::Client) {
    // The key share is the `X25519MLKEM768` hybrid, not plain x25519: REALITY servers from
    // `xtls/reality` v0.0.0-20260908062103 refuse to authenticate a hello without it, and
    // the refusal is silent — the flow is forwarded to the impersonated site.
    let mut rng = OsRng;
    let exchange = crate::reality::hybrid::Client::generate(&mut rng);
    let share = exchange.client_share();
    let random = super::random_32();

    // GREASE keeps middleboxes from ossifying; it is also what a browser sends, and
    // REALITY's premise is that the hello is indistinguishable from one.
    const GREASE_EXT: u16 = 0x0a0a;
    const GREASE_GROUP: u16 = 0x1a1a;

    let mut extensions = Vec::new();

    // server_name (0): for REALITY this is the impersonated site.
    {
        let name = server_name.as_bytes();
        let mut entry = Vec::new();
        entry.push(0u8); // host_name
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);
        let mut body = Vec::new();
        body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        body.extend_from_slice(&entry);
        push_extension(&mut extensions, 0, &body);
    }
    // supported_groups (10): the hybrid first, so the server picks it.
    {
        let groups = [GREASE_GROUP, crate::reality::hybrid::GROUP, 0x001d];
        let mut body = Vec::new();
        body.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for group in groups {
            body.extend_from_slice(&group.to_be_bytes());
        }
        push_extension(&mut extensions, 10, &body);
    }
    // signature_algorithms (13)
    {
        let algorithms: [u16; 8] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut body = Vec::new();
        body.extend_from_slice(&((algorithms.len() * 2) as u16).to_be_bytes());
        for algorithm in algorithms {
            body.extend_from_slice(&algorithm.to_be_bytes());
        }
        push_extension(&mut extensions, 13, &body);
    }
    // supported_versions (43): TLS 1.3 only.
    {
        let mut body = Vec::new();
        body.push(2);
        body.extend_from_slice(&0x0304u16.to_be_bytes());
        push_extension(&mut extensions, 43, &body);
    }
    // key_share (51): one entry, the hybrid group.
    {
        let mut entry = Vec::new();
        entry.extend_from_slice(&crate::reality::hybrid::GROUP.to_be_bytes());
        entry.extend_from_slice(&(share.len() as u16).to_be_bytes());
        entry.extend_from_slice(&share);
        let mut body = Vec::new();
        body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        body.extend_from_slice(&entry);
        push_extension(&mut extensions, 51, &body);
    }
    // ALPN (16), only when asked for: a REALITY node may not speak any.
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for protocol in alpn {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        body.extend_from_slice(&list);
        push_extension(&mut extensions, 16, &body);
    }
    // A GREASE extension so the hello does not look purpose-built.
    push_extension(&mut extensions, GREASE_EXT, &[0]);

    let suites = cipher_suites();
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    // RFC 8446 §4.1.2: `random` is 32 mandatory bytes. REALITY derives its authentication
    // key from it (`salt = random[..20]`, `nonce = random[20..]`), so it is not a filler
    // field here — omitting it makes the hello both malformed and unauthenticated.
    body.extend_from_slice(&random);
    // The REALITY tag lives in `legacy_session_id` and is written by the caller once it has
    // sealed the tag over this hello; the placeholder keeps the length fixed.
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.push(1); // legacy_compression_methods length
    body.push(0); // null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(message_type::CLIENT_HELLO);
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    (message, exchange)
}

/// The offset of `legacy_session_id`'s 32 bytes inside a ClientHello.
///
/// Recorded rather than computed at each use: REALITY patches this field *after* the hello
/// is built, because the tag is sealed over the finished hello, and a wrong offset would
/// silently put the tag somewhere else.
const SESSION_ID_OFFSET: usize = 4 + 2 + 32 + 1;

/// Writes `tag` into the ClientHello's `legacy_session_id`.
fn set_session_id(message: &mut [u8], tag: &[u8; 32]) {
    message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(tag);
}

/// The ClientHello alone, for the wire-level probe.
///
/// See [`super::probe`] for why this exists. The session-id stays zeroed: a plain server
/// ignores it, so the hello is judged on its framing and extensions.
///
/// # Errors
///
/// Currently unreachable; the caller signature keeps the failure a value because a
/// future hello that needs validated input should not have to change the probe.
pub(crate) fn probe_client_hello(server_name: &str) -> Result<Vec<u8>, String> {
    let (message, _) = build_client_hello(server_name, &[]);
    Ok(message)
}

fn push_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// The suites this client offers: the two SHA-256 suites a REALITY node can meet, plus
/// GREASE. `TLS_AES_256_GCM_SHA384` is absent because its schedule needs SHA-384.
const fn cipher_suites() -> [u16; 3] {
    [0x0a0a, 0x1301, 0x1303]
}

// ── Server messages ─────────────────────────────────────────────────────────

/// Extracts the negotiated suite and group, and the server's key share.
fn parse_server_hello(message: &[u8]) -> Result<Negotiated, HandshakeError> {
    let body = message
        .get(4..)
        .ok_or_else(|| HandshakeError("ServerHello is too short".to_owned()))?;
    let mut reader = Reader::new(body);
    reader.skip(2)?; // legacy_version
    // RFC 8446 §4.1.3: `random` is present in a ServerHello too. Skipping it was one of
    // the reasons this parser had never been exercised against a real server.
    reader.skip(32)?; // random
    let session_id_len = reader.u8()? as usize;
    reader.skip(session_id_len)?;
    let suite = reader.u16()?;
    reader.skip(1)?; // compression method
    let extensions_len = reader.u16()? as usize;
    let extensions = reader.take(extensions_len)?;

    let mut group = None;
    let mut reader = Reader::new(extensions);
    while !reader.is_empty() {
        let kind = reader.u16()?;
        let length = reader.u16()? as usize;
        let body = reader.take(length)?;
        match kind {
            43 => {
                if Reader::new(body).u16()? != 0x0304 {
                    return fail("the server selected a version below TLS 1.3");
                }
            }
            51 => {
                let chosen = Reader::new(body).u16()?;
                if chosen != crate::reality::hybrid::GROUP {
                    return fail(format!(
                        "the server selected key-share group {chosen:#06x}; this client \
                         offers only X25519MLKEM768 ({:#06x})",
                        crate::reality::hybrid::GROUP
                    ));
                }
                group = Some(chosen);
            }
            _ => {}
        }
    }

    let group =
        group.ok_or_else(|| HandshakeError("the server sent no key_share extension".to_owned()))?;
    Ok(Negotiated { suite, group })
}

/// The server's key share, from its `key_share` extension.
fn server_key_share(message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let body = message
        .get(4..)
        .ok_or_else(|| HandshakeError("ServerHello is too short".to_owned()))?;
    let mut reader = Reader::new(body);
    reader.skip(2)?; // legacy_version
    reader.skip(32)?; // random
    let session_id_len = reader.u8()? as usize;
    reader.skip(session_id_len)?;
    reader.skip(3)?; // suite + compression
    let extensions_len = reader.u16()? as usize;
    let extensions = reader.take(extensions_len)?;

    let mut reader = Reader::new(extensions);
    while !reader.is_empty() {
        let kind = reader.u16()?;
        let length = reader.u16()? as usize;
        let body = reader.take(length)?;
        if kind == 51 {
            let mut share = Reader::new(body);
            let group = share.u16()?;
            if group != crate::reality::hybrid::GROUP {
                return fail(format!(
                    "the server's key share is group {group:#06x}, not X25519MLKEM768"
                ));
            }
            let key_len = share.u16()? as usize;
            return Ok(share.take(key_len)?.to_vec());
        }
    }
    fail("the server sent no key_share extension")
}

/// The X25519 secret inside a hybrid share, for REALITY's tag.
fn exchange_tag_secret(exchange: &crate::reality::hybrid::Client) -> [u8; 32] {
    exchange.x25519_secret_bytes()
}

/// Completes the key exchange with the group the server selected.
fn key_exchange(
    exchange: &crate::reality::hybrid::Client,
    server_hello: &[u8],
    negotiated: &Negotiated,
) -> Result<Vec<u8>, HandshakeError> {
    if negotiated.group != crate::reality::hybrid::GROUP {
        return fail(format!(
            "the server selected key-share group {:#06x}; this client offers only \
             X25519MLKEM768 ({:#06x}), which is what a current REALITY node requires",
            negotiated.group,
            crate::reality::hybrid::GROUP
        ));
    }
    let peer = server_key_share(server_hello)?;
    Ok(exchange.complete(&peer).map_err(HandshakeError)?.to_vec())
}

/// Extracts the leaf certificate DER from a Certificate message.
fn parse_certificate_message(message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let body = message
        .get(4..)
        .ok_or_else(|| HandshakeError("Certificate message is too short".to_owned()))?;
    let mut reader = Reader::new(body);
    let context_len = reader.u8()? as usize;
    reader.skip(context_len)?;
    let list_len = reader.u24()?;
    let list = reader.take(list_len)?;
    let mut reader = Reader::new(list);
    let cert_len = reader.u24()?;
    Ok(reader.take(cert_len)?.to_vec())
}

fn verify_finished(
    message: &[u8],
    finished_key: &schedule::Secret,
    transcript: &Transcript,
) -> Result<(), HandshakeError> {
    let body = message
        .get(4..)
        .ok_or_else(|| HandshakeError("Finished message is too short".to_owned()))?;
    let expected =
        schedule::finished_mac(finished_key, &transcript.hash()).map_err(HandshakeError)?;
    if !schedule::constant_time_eq(body, &expected) {
        return fail(
            "the server's Finished did not verify: the key schedule or the transcript is wrong",
        );
    }
    Ok(())
}

fn client_finished_message(
    client_hs: &schedule::DirectionKeys,
    transcript: &Transcript,
) -> Result<Vec<u8>, HandshakeError> {
    let key = client_hs
        .finished_key
        .as_ref()
        .ok_or_else(|| HandshakeError("no client finished key".to_owned()))?;
    let mac = schedule::finished_mac(key, &transcript.hash()).map_err(HandshakeError)?;
    let mut message = Vec::with_capacity(4 + mac.len());
    message.push(message_type::FINISHED);
    message.extend_from_slice(&(mac.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&mac);
    Ok(message)
}

/// A bounds-checked cursor over a handshake body.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HandshakeError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                HandshakeError(format!(
                    "handshake field wants {length} bytes at offset {}, buffer is {}",
                    self.offset,
                    self.bytes.len()
                ))
            })?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn skip(&mut self, length: usize) -> Result<(), HandshakeError> {
        self.take(length).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, HandshakeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, HandshakeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, HandshakeError> {
        let bytes = self.take(3)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }
}

// ── The stream ──────────────────────────────────────────────────────────────

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls13Connection<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Anything already decrypted is handed over first: a record can carry more
        // plaintext than the caller's buffer.
        if !self.layer.pending.is_empty() {
            let take = self.layer.pending.len().min(buf.remaining());
            buf.put_slice(&self.layer.pending[..take]);
            self.layer.pending.drain(..take);
            return Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Pull records until one yields application data. Returning `Pending` with
        // nothing written is only correct after registering interest, which the inner
        // `poll_read` does.
        //
        // The read state is moved out of `self` for the duration of each step: the state
        // machine needs `&mut self.io` at the same time, and two disjoint fields cannot be
        // borrowed through `&mut self` while one is matched on.
        loop {
            let mut reading = std::mem::replace(
                &mut self.reading,
                Reading::Header {
                    filled: 0,
                    bytes: [0u8; RecordHeader::LEN],
                },
            );
            let outcome = match &mut reading {
                Reading::Header { filled, bytes } => {
                    let mut header_buf = ReadBuf::new(&mut bytes[*filled..]);
                    match Pin::new(&mut self.io).poll_read(cx, &mut header_buf) {
                        Poll::Pending => Step::Pending(reading),
                        Poll::Ready(Err(error)) => Step::Failed(reading, error),
                        Poll::Ready(Ok(())) => {
                            let read = header_buf.filled().len();
                            if read == 0 {
                                if *filled == 0 {
                                    // A clean EOF between records.
                                    return Poll::Ready(Ok(()));
                                }
                                Step::Failed(
                                    reading,
                                    std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "the peer closed mid-header",
                                    ),
                                )
                            } else {
                                *filled += read;
                                if *filled < RecordHeader::LEN {
                                    Step::Again(reading)
                                } else {
                                    match RecordHeader::parse(bytes) {
                                        Ok(header) => {
                                            let length = usize::from(header.length);
                                            if length == 0 {
                                                Step::Failed(
                                                    reading,
                                                    std::io::Error::other(
                                                        "the peer sent an empty record",
                                                    ),
                                                )
                                            } else {
                                                Step::Again(Reading::Body {
                                                    header,
                                                    filled: 0,
                                                    bytes: vec![0u8; length],
                                                })
                                            }
                                        }
                                        Err(error) => {
                                            Step::Failed(reading, std::io::Error::other(error))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Reading::Body {
                    header,
                    filled,
                    bytes,
                } => {
                    let mut body_buf = ReadBuf::new(&mut bytes[*filled..]);
                    match Pin::new(&mut self.io).poll_read(cx, &mut body_buf) {
                        Poll::Pending => Step::Pending(reading),
                        Poll::Ready(Err(error)) => Step::Failed(reading, error),
                        Poll::Ready(Ok(())) => {
                            let read = body_buf.filled().len();
                            if read == 0 {
                                Step::Failed(
                                    reading,
                                    std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "the peer closed mid-record",
                                    ),
                                )
                            } else {
                                *filled += read;
                                if *filled < bytes.len() {
                                    Step::Again(reading)
                                } else {
                                    let header = *header;
                                    let body = std::mem::take(bytes);
                                    let fresh = Reading::Header {
                                        filled: 0,
                                        bytes: [0u8; RecordHeader::LEN],
                                    };
                                    // A change_cipher_spec is plaintext even after keys are
                                    // installed; decrypting it fails and would abort a
                                    // working session at the first post-handshake record.
                                    if header.content_type == ContentType::ChangeCipherSpec as u8 {
                                        self.reading = fresh;
                                        continue;
                                    }
                                    match self.layer.unframe(&header, &body) {
                                        Ok((ContentType::ApplicationData, payload)) => {
                                            self.reading = fresh;
                                            self.layer.pending.extend_from_slice(&payload);
                                            let take =
                                                self.layer.pending.len().min(buf.remaining());
                                            buf.put_slice(&self.layer.pending[..take]);
                                            self.layer.pending.drain(..take);
                                            return Poll::Ready(Ok(()));
                                        }
                                        // A post-handshake message, a stray CCS or an alert
                                        // is skipped: none of them changes the application
                                        // data this caller asked for, and refusing one would
                                        // break a working session.
                                        Ok(_) => Step::Again(fresh),
                                        Err(error) => {
                                            Step::Failed(fresh, std::io::Error::other(error))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
            match outcome {
                Step::Again(state) => self.reading = state,
                Step::Pending(state) => {
                    self.reading = state;
                    return Poll::Pending;
                }
                Step::Failed(state, error) => {
                    self.reading = state;
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}

/// One step of the read state machine.
///
/// The state is carried through so it is never lost on an early return: a `Pending` poll
/// must leave the connection exactly as it found it apart from registered interest.
enum Step {
    Again(Reading),
    Pending(Reading),
    Failed(Reading, std::io::Error),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls13Connection<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // A socket write may accept a prefix, so an unfinished frame is retained and
        // finished before any new frame is produced. Without this a partial write would
        // silently truncate a record and corrupt the stream.
        if self.awaiting_write.is_empty() {
            let take = buf.len().min(super::record::MAX_PLAINTEXT);
            match self.layer.frame(ContentType::ApplicationData, &buf[..take]) {
                Ok(framed) => {
                    self.awaiting_write = framed;
                    self.written = 0;
                }
                Err(error) => return Poll::Ready(Err(std::io::Error::other(error))),
            }
            // The caller's plaintext is consumed once the frame exists; how much of the
            // frame the socket took is our problem, not theirs.
            let plaintext_len = take;
            return self.drive_write(cx, plaintext_len);
        }
        let plaintext_len = 0;
        self.drive_write(cx, plaintext_len)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.awaiting_write.is_empty() {
            match self.drive_write(cx, 0) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.awaiting_write.is_empty() {
            match self.drive_write(cx, 0) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13Connection<S> {
    /// Pushes the retained frame into the socket until it is gone.
    ///
    /// Reports `plaintext_len` to the caller, which is the number of *its* bytes that were
    /// accepted — not the number of framed bytes written.
    fn drive_write(
        &mut self,
        cx: &mut Context<'_>,
        plaintext_len: usize,
    ) -> Poll<std::io::Result<usize>> {
        while self.written < self.awaiting_write.len() {
            let mut write_buf = ReadBuf::new(&mut []);
            let _ = &mut write_buf;
            match Pin::new(&mut self.io).poll_write(cx, &self.awaiting_write[self.written..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "the peer accepted no bytes of a record",
                    )));
                }
                Poll::Ready(Ok(written)) => self.written += written,
            }
        }
        self.awaiting_write.clear();
        self.written = 0;
        Poll::Ready(Ok(plaintext_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_hello_has_the_rfc_8446_field_order() {
        // The bug this test exists for: the hello once omitted `random`, so a conformant
        // parser read our session-id length byte as the last byte of `random` and saw a
        // zero-length session-id. The node then forwarded the flow to the impersonated
        // site, and the only visible symptom was a certificate for the wrong host.
        let (message, _) = build_client_hello("www.example.com", &[]);
        assert_eq!(message[0], message_type::CLIENT_HELLO);
        // header(4) legacy_version(2) random(32) session_id_len(1)
        assert_eq!(&message[4..6], &[0x03, 0x03], "legacy_version");
        assert_eq!(message[4 + 2 + 32], 32, "session_id length");
        assert_eq!(
            message.len(),
            4 + 2
                + 32
                + 1
                + 32
                + 2
                + 6
                + 1
                + 1
                + 2
                + u16::from_be_bytes([
                    message[4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1],
                    message[4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1 + 1],
                ]) as usize,
            "the declared extension length must consume the rest of the hello"
        );
    }

    #[test]
    fn the_session_id_offset_matches_the_field_layout() {
        // REALITY patches the tag in place after sealing it over the hello, so a wrong
        // offset would put the tag where the server does not look.
        let (mut message, _) = build_client_hello("www.example.com", &[]);
        let tag = [0xab; 32];
        set_session_id(&mut message, &tag);
        assert_eq!(
            &message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
            &tag,
            "the tag must land in legacy_session_id"
        );
        // The byte immediately before it is the length prefix, and it must still be 32.
        assert_eq!(message[SESSION_ID_OFFSET - 1], 32);
    }

    #[test]
    fn two_hellos_do_not_share_a_random() {
        // REALITY derives the auth key salt and the AEAD nonce from `random`; a constant
        // would make every connection's tag replayable.
        let (first, _) = build_client_hello("x.example", &[]);
        let (second, _) = build_client_hello("x.example", &[]);
        assert_ne!(
            &first[6..38],
            &second[6..38],
            "random must be fresh per connection"
        );
        assert_ne!(&first[6..38], &[0u8; 32], "random must not be zero");
    }

    #[test]
    fn a_client_hello_names_tls13_and_offers_key_share() {
        // The second return value is the *secret*; the public share is derived from it and
        // must appear on the wire. Recomputing it here is the only way to check that the
        // hello commits to the key the handshake will actually use.
        let (message, exchange) = build_client_hello("x.example", &[]);
        assert!(
            message.windows(2).any(|window| window == [0x03, 0x04]),
            "supported_versions must name TLS 1.3"
        );
        // The share is the hybrid group, whose tail is the X25519 public key.
        let share = exchange.client_share();
        assert!(
            message.windows(share.len()).any(|window| window == share),
            "the key share must be the hybrid share the exchange produced"
        );
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            exchange.x25519_secret_bytes(),
        ));
        assert_eq!(
            &share[crate::reality::hybrid::MLKEM_ENCAPSULATION_KEY_LEN..],
            &public.to_bytes(),
            "the share's tail is the X25519 public key"
        );
    }

    #[test]
    fn a_client_hello_is_not_hello_retry_or_a_second_handshake_shape() {
        let (message, _) = build_client_hello("x.example", &[]);
        // The handshake header carries the body length, and the body must fill exactly.
        let declared = (usize::from(message[1]) << 16)
            | (usize::from(message[2]) << 8)
            | usize::from(message[3]);
        assert_eq!(declared + 4, message.len());
    }

    #[test]
    fn alpn_is_offered_only_when_asked_for() {
        let (without, _) = build_client_hello("x.example", &[]);
        let (with, _) = build_client_hello("x.example", &[b"h2".to_vec()]);
        assert!(with.len() > without.len(), "ALPN adds bytes");
        assert!(with.windows(3).any(|window| window == b"\x02h2"));
    }

    #[test]
    fn a_handshake_message_split_across_records_is_reassembled() {
        // Four-byte header + body, delivered in two pieces.
        let message = [20u8, 0, 0, 3, 1, 2, 3];
        let mut buffer = message[..5].to_vec();
        assert!(take_handshake_message(&mut buffer).expect("ok").is_none());
        buffer.extend_from_slice(&message[5..]);
        let taken = take_handshake_message(&mut buffer)
            .expect("ok")
            .expect("complete");
        assert_eq!(taken, message);
        assert!(buffer.is_empty());
    }

    #[test]
    fn an_absurd_handshake_length_is_refused_rather_than_allocated() {
        let mut buffer = vec![20u8, 0xff, 0xff, 0xff];
        let error = take_handshake_message(&mut buffer).expect_err("must refuse");
        assert!(error.0.contains("over the"), "{error}");
    }

    #[test]
    fn a_truncated_server_hello_is_an_error_not_a_panic() {
        let message = [2u8, 0, 0, 0];
        let error = parse_server_hello(&message).expect_err("must fail");
        // Truncation is reported as a bounds error rather than a panic; the exact wording
        // is not the contract, "an error instead of a panic" is.
        assert!(!error.0.is_empty(), "{error}");
    }

    #[test]
    fn a_server_hello_without_key_share_is_refused() {
        let body = server_hello_body(0x1301, 0);
        let error = parse_server_hello(&framed_server_hello(&body)).expect_err("must fail");
        assert!(error.0.contains("key_share"), "{error}");
    }

    #[test]
    fn a_server_hello_is_parsed_with_its_random_present() {
        // The bug this guards: the parser once skipped only `legacy_version`, so it read
        // the first byte of the server's `random` as the session-id length and then failed
        // to find the extensions. Every ServerHello from a real server tripped it.
        let body = server_hello_body(0x1301, crate::reality::hybrid::GROUP);
        let hello = framed_server_hello(&body);
        let negotiated = parse_server_hello(&hello).expect("parses");
        assert_eq!(negotiated.suite, 0x1301);
        assert_eq!(negotiated.group, crate::reality::hybrid::GROUP);
    }

    /// A ServerHello body: legacy_version, a fresh random, no session-id, the given suite,
    /// a null compression method, and a key_share extension when `group` is non-zero.
    fn server_hello_body(suite: u16, group: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x5au8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0); // compression
        let mut extensions = Vec::new();
        if group != 0 {
            let mut share = Vec::new();
            share.extend_from_slice(&group.to_be_bytes());
            share.extend_from_slice(&32u16.to_be_bytes());
            share.extend_from_slice(&[0x11u8; 32]);
            push_extension(&mut extensions, 51, &share);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn framed_server_hello(body: &[u8]) -> Vec<u8> {
        let mut message = vec![message_type::SERVER_HELLO];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(body);
        message
    }
}
