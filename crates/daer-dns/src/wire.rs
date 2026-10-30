// SPDX-License-Identifier: AGPL-3.0-only

//! The DNS wire format: just enough to route, cache and rewrite.
//!
//! # Why this is not a dependency
//!
//! A resolver that only needs to *read* a question and *rewrite* a TTL needs very
//! little of RFC 1035: the header, the question section, the resource-record framing
//! and name compression. Pulling in a full DNS stack would add a parser, an encoder, a
//! signing stack and a zone file reader that this project would never execute — and the
//! parsers that *are* executed would be someone else's, on the path every query takes.
//! Owning ~400 lines here keeps the executed surface small and reviewable.
//!
//! # What is deliberately absent
//!
//! * **No name compression on encode.** Compressing the names this crate writes would
//!   save a few bytes per answer and cost a second encoder to keep in sync with the
//!   parser. Records that are rewritten (a TTL, an injected A record) are written
//!   uncompressed, which every resolver accepts.
//! * **No EDNS0 option rewriting.** The OPT record is preserved verbatim; its options
//!   belong to the client and the upstream, not to a forwarder.
//! * **No DNSSEC validation.** Signatures are carried through untouched: a forwarder
//!   that cannot validate must not pretend to, and stripping them would break clients
//!   that do.
//!
//! # Safety of the parser
//!
//! Every read is bounds-checked and every length is validated against the remaining
//! buffer. A malformed packet yields [`ParseError`], never a panic: the input arrives
//! from the network, so it is hostile by default. Compression pointers are followed with
//! an explicit hop budget and may only point backwards, which is what makes the classic
//! decompression bomb impossible.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A DNS name, kept as labels so it can be re-encoded without a second parse.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// Builds a name from labels.
    #[must_use]
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Self {
        Self { labels }
    }

    /// Parses a presentation-format name (`example.com`, with or without a trailing
    /// dot). Labels are ASCII case-preserved; comparison is case-insensitive
    /// ([`Name::eq_ignore_case`]), which is what DNS requires.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::BadName`] for an empty label, a label over 63 octets, or a
    /// name over 253 octets.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Ok(Self::root());
        }
        let mut labels = Vec::new();
        for label in text.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(ParseError::BadName(text.to_owned()));
            }
            labels.push(label.as_bytes().to_vec());
        }
        let name = Self { labels };
        if name.wire_len() > 255 {
            return Err(ParseError::BadName(text.to_owned()));
        }
        Ok(name)
    }

    /// The root name (`.`).
    #[must_use]
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// The labels, outermost first.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// True for the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Byte length in uncompressed wire form, including the root's zero octet.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1
    }

    /// Case-insensitive equality, as DNS name comparison requires.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(&other.labels)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// True when this name is `suffix` or ends with `.suffix`, case-insensitively.
    #[must_use]
    pub fn ends_with(&self, suffix: &Self) -> bool {
        if suffix.labels.len() > self.labels.len() {
            return false;
        }
        self.labels[self.labels.len() - suffix.labels.len()..]
            .iter()
            .zip(&suffix.labels)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// The name as text, without a trailing dot.
    #[must_use]
    pub fn to_text(&self) -> String {
        self.labels
            .iter()
            .map(|label| String::from_utf8_lossy(label).into_owned())
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        f.write_str(&self.to_text())
    }
}

/// Record types this crate names. Others are carried as their number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(pub u16);

impl RecordType {
    pub const A: Self = Self(1);
    pub const NS: Self = Self(2);
    pub const CNAME: Self = Self(5);
    pub const SOA: Self = Self(6);
    pub const AAAA: Self = Self(28);
    pub const OPT: Self = Self(41);
    pub const HTTPS: Self = Self(65);

    /// Parses a configuration spelling: `A`, `AAAA`, `HTTPS`, or a number.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::UnknownRecordType`] for anything else. Refusing an
    /// unknown mnemonic is deliberate: silently ignoring it would make a rule that
    /// restricts nothing look like a rule.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let upper = text.trim().to_ascii_uppercase();
        Ok(match upper.as_str() {
            "A" => Self::A,
            "NS" => Self::NS,
            "CNAME" => Self::CNAME,
            "SOA" => Self::SOA,
            "AAAA" => Self::AAAA,
            "OPT" => Self::OPT,
            "HTTPS" => Self::HTTPS,
            other => match other.parse::<u16>() {
                Ok(number) => Self(number),
                Err(_) => return Err(ParseError::UnknownRecordType(other.to_owned())),
            },
        })
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::A => f.write_str("A"),
            Self::NS => f.write_str("NS"),
            Self::CNAME => f.write_str("CNAME"),
            Self::SOA => f.write_str("SOA"),
            Self::AAAA => f.write_str("AAAA"),
            Self::OPT => f.write_str("OPT"),
            Self::HTTPS => f.write_str("HTTPS"),
            Self(number) => write!(f, "TYPE{number}"),
        }
    }
}

/// Response codes this crate distinguishes. Others are carried as their number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode(pub u16);

impl ResponseCode {
    pub const NOERROR: Self = Self(0);
    pub const FORMERR: Self = Self(1);
    pub const SERVFAIL: Self = Self(2);
    pub const NXDOMAIN: Self = Self(3);
    pub const REFUSED: Self = Self(5);
}

/// One question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: u16,
}

impl Question {
    /// The usual class, `IN`.
    pub const CLASS_IN: u16 = 1;

    #[must_use]
    pub fn internet(name: Name, qtype: RecordType) -> Self {
        Self {
            name,
            qtype,
            qclass: Self::CLASS_IN,
        }
    }
}

/// One resource record, with its RDATA carried as raw bytes.
///
/// Raw bytes rather than a per-type enum: a forwarder must be able to pass through
/// record types it does not understand, and re-encoding a decoded record is a way to
/// corrupt it. Only the framing is parsed, which is also the only part that needs to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl Record {
    /// True for the EDNS0 OPT pseudo-record, which is not an answer.
    #[must_use]
    pub fn is_opt(&self) -> bool {
        self.rtype == RecordType::OPT
    }

    /// The address of an `A` record.
    #[must_use]
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        (self.rtype == RecordType::A && self.rdata.len() == 4)
            .then(|| Ipv4Addr::new(self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]))
    }

    /// The address of an `AAAA` record.
    #[must_use]
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        (self.rtype == RecordType::AAAA && self.rdata.len() == 16).then(|| {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.rdata);
            Ipv6Addr::from(octets)
        })
    }
}

/// Flags kept as bits so a forwarder can pass through what it does not interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u16);

impl Flags {
    const QR: u16 = 0x8000;
    const TC: u16 = 0x0200;
    const RD: u16 = 0x0100;
    const RA: u16 = 0x0080;

    /// True for a response.
    #[must_use]
    pub const fn is_response(self) -> bool {
        self.0 & Self::QR != 0
    }

    /// Recursion desired.
    #[must_use]
    pub const fn recursion_desired(self) -> bool {
        self.0 & Self::RD != 0
    }

    /// Recursion available.
    #[must_use]
    pub const fn recursion_available(self) -> bool {
        self.0 & Self::RA != 0
    }

    /// Truncated: the answer did not fit the transport and the client must retry
    /// over TCP (RFC 1035 §4.2.1).
    #[must_use]
    pub const fn is_truncated(self) -> bool {
        self.0 & Self::TC != 0
    }

    /// The response code, from the low four bits.
    #[must_use]
    pub const fn response_code(self) -> ResponseCode {
        ResponseCode(self.0 & 0x000f)
    }

    /// A response to `request`, with `code`, echoing recursion availability.
    #[must_use]
    pub fn response_to(request: Self, code: ResponseCode) -> Self {
        let qr_ra = Self::QR | Self::RA;
        let rd = request.0 & Self::RD;
        Self(qr_ra | rd | (code.0 & 0x000f))
    }
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    /// True for a response.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags.is_response()
    }

    /// The response code.
    #[must_use]
    pub const fn response_code(&self) -> ResponseCode {
        self.flags.response_code()
    }

    /// The single question, when the message has exactly one.
    ///
    /// A forwarder only routes on a single question; a packet with two is unusual and
    /// is passed through rather than guessed at.
    #[must_use]
    pub fn single_question(&self) -> Option<&Question> {
        match self.questions.as_slice() {
            [question] => Some(question),
            _ => None,
        }
    }

    /// Every `A`/`AAAA` address in the answer section, in order.
    #[must_use]
    pub fn answer_addresses(&self) -> Vec<std::net::IpAddr> {
        self.answers
            .iter()
            .filter_map(|record| {
                record
                    .as_ipv4()
                    .map(std::net::IpAddr::V4)
                    .or_else(|| record.as_ipv6().map(std::net::IpAddr::V6))
            })
            .collect()
    }

    /// A minimal `SERVFAIL`-style reply to `request`, echoing the question.
    ///
    /// Used for a request that cannot be served: the client must get an answer rather
    /// than a timeout, because a timeout makes it retry and hold the slot.
    #[must_use]
    pub fn reply_to(request: &Self, code: ResponseCode) -> Self {
        Self {
            id: request.id,
            flags: Flags::response_to(request.flags, code),
            questions: request.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

/// A minimal recursive query for `name`/`qtype`.
///
/// Public because a resolver's callers (an upstream transport's tests, a health probe)
/// need to build a well-formed question without re-deriving the header flags. `RD` is set
/// because a resolver asking an upstream always wants recursion.
pub fn query(id: u16, name: &str, qtype: RecordType) -> Result<Message, ParseError> {
    Ok(Message {
        id,
        flags: Flags(0x0100),
        questions: vec![Question::internet(Name::parse(name)?, qtype)],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    })
}

/// A reply to `request` carrying `answers`.
///
/// `RA` and `QR` are set, the question is echoed, and the response code is `NOERROR`.
/// An upstream transport's tests use it to stand in for a real server without
/// re-implementing the header.
#[must_use]
pub fn reply(request: &Message, answers: &[Record]) -> Message {
    Message {
        id: request.id,
        flags: Flags::response_to(request.flags, ResponseCode::NOERROR),
        questions: request.questions.clone(),
        answers: answers.to_vec(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// A parse error. Never produced for a well-formed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the header requires.
    Truncated,
    /// A question or record count that does not fit the buffer.
    TruncatedSection {
        section: &'static str,
        index: usize,
    },
    /// A compression pointer that loops, points forward, or exceeds the hop budget.
    BadPointer,
    /// A label that runs past the buffer or over 63 octets.
    BadLabel,
    /// A name over 255 octets, or an empty/malformed presentation-format name.
    BadName(String),
    /// A label set that is not valid UTF-8 in a place where text is required.
    NotText,
    UnknownRecordType(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("message shorter than a DNS header"),
            Self::TruncatedSection { section, index } => {
                write!(f, "truncated {section} section at entry {index}")
            }
            Self::BadPointer => f.write_str("invalid name compression pointer"),
            Self::BadLabel => f.write_str("invalid label"),
            Self::BadName(name) => write!(f, "invalid DNS name {name:?}"),
            Self::NotText => f.write_str("a name label is not valid text"),
            Self::UnknownRecordType(text) => write!(f, "unknown DNS record type {text:?}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Maximum number of compression pointers followed for one name.
///
/// The spec allows a pointer anywhere earlier in the packet, so a hostile packet can
/// chain them into a loop of length N with N hops. A budget bounds the work; a
/// backwards-only rule bounds it to the packet length. Both are applied.
const MAX_POINTER_HOPS: usize = 128;

/// Parses a DNS message.
///
/// # Errors
///
/// Returns [`ParseError`] for any malformed input. Never panics, never reads out of
/// bounds, never loops: the buffer comes from the network.
pub fn parse(buffer: &[u8]) -> Result<Message, ParseError> {
    if buffer.len() < 12 {
        return Err(ParseError::Truncated);
    }
    let id = u16::from_be_bytes([buffer[0], buffer[1]]);
    let flags = Flags(u16::from_be_bytes([buffer[2], buffer[3]]));
    let counts = [
        u16::from_be_bytes([buffer[4], buffer[5]]),
        u16::from_be_bytes([buffer[6], buffer[7]]),
        u16::from_be_bytes([buffer[8], buffer[9]]),
        u16::from_be_bytes([buffer[10], buffer[11]]),
    ];

    let mut offset = 12;
    let mut questions = Vec::with_capacity(usize::from(counts[0]));
    for index in 0..usize::from(counts[0]) {
        let (name, next) = read_name(buffer, offset)?;
        offset = next;
        let qtype = read_u16(buffer, offset).ok_or(ParseError::TruncatedSection {
            section: "question",
            index,
        })?;
        let qclass = read_u16(buffer, offset + 2).ok_or(ParseError::TruncatedSection {
            section: "question",
            index,
        })?;
        offset += 4;
        questions.push(Question {
            name,
            qtype: RecordType(qtype),
            qclass,
        });
    }

    let mut sections = [
        ("answer", Vec::with_capacity(usize::from(counts[1]))),
        ("authority", Vec::with_capacity(usize::from(counts[2]))),
        ("additional", Vec::with_capacity(usize::from(counts[3]))),
    ];
    for (section_index, (section, records)) in sections.iter_mut().enumerate() {
        let count = usize::from(counts[section_index + 1]);
        for index in 0..count {
            let record = read_record(buffer, &mut offset, section, index)?;
            records.push(record);
        }
    }
    let [answers, authorities, additionals] = sections;

    Ok(Message {
        id,
        flags,
        questions,
        answers: answers.1,
        authorities: authorities.1,
        additionals: additionals.1,
    })
}

fn read_record(
    buffer: &[u8],
    offset: &mut usize,
    section: &'static str,
    index: usize,
) -> Result<Record, ParseError> {
    let truncated = || ParseError::TruncatedSection { section, index };
    let (name, next) = read_name(buffer, *offset)?;
    *offset = next;

    let rtype = read_u16(buffer, *offset).ok_or_else(truncated)?;
    let class = read_u16(buffer, *offset + 2).ok_or_else(truncated)?;
    let ttl = read_u32(buffer, *offset + 4).ok_or_else(truncated)?;
    let length = usize::from(read_u16(buffer, *offset + 8).ok_or_else(truncated)?);
    *offset += 10;

    let end = offset.checked_add(length).ok_or_else(truncated)?;
    let rdata = buffer.get(*offset..end).ok_or_else(truncated)?.to_vec();
    *offset = end;

    Ok(Record {
        name,
        rtype: RecordType(rtype),
        class,
        ttl,
        rdata,
    })
}

/// Reads a possibly compressed name, returning it and the offset just past it.
fn read_name(buffer: &[u8], start: usize) -> Result<(Name, usize), ParseError> {
    let mut labels = Vec::new();
    let mut offset = start;
    // Where to resume after the first pointer: the bytes after the pointer are the
    // rest of the *original* field, and the pointer only redirects the name.
    let mut resume = None;
    let mut hops = 0usize;

    loop {
        let length = *buffer.get(offset).ok_or(ParseError::BadLabel)?;
        match length & 0xc0 {
            0x00 => {
                if length == 0 {
                    let end = resume.unwrap_or(offset + 1);
                    let name = Name::from_labels(labels);
                    if name.wire_len() > 255 {
                        return Err(ParseError::BadName(name.to_text()));
                    }
                    return Ok((name, end));
                }
                let label_start = offset + 1;
                let label_end = label_start + usize::from(length);
                let label = buffer
                    .get(label_start..label_end)
                    .ok_or(ParseError::BadLabel)?;
                labels.push(label.to_vec());
                offset = label_end;
            }
            0xc0 => {
                let low = *buffer.get(offset + 1).ok_or(ParseError::BadPointer)?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
                // Backwards only: a forward pointer is a loop once the packet is
                // interpreted as a graph, and no encoder emits one.
                if target >= offset {
                    return Err(ParseError::BadPointer);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(ParseError::BadPointer);
                }
                resume.get_or_insert(offset + 2);
                offset = target;
            }
            _ => return Err(ParseError::BadLabel),
        }
    }
}

fn read_u16(buffer: &[u8], at: usize) -> Option<u16> {
    let bytes = buffer.get(at..at + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buffer: &[u8], at: usize) -> Option<u32> {
    let bytes = buffer.get(at..at + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Encodes a message.
///
/// Names are written uncompressed; see the module documentation for why.
#[must_use]
pub fn encode(message: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&message.id.to_be_bytes());
    out.extend_from_slice(&message.flags.0.to_be_bytes());
    for count in [
        message.questions.len(),
        message.answers.len(),
        message.authorities.len(),
        message.additionals.len(),
    ] {
        out.extend_from_slice(&(count as u16).to_be_bytes());
    }
    for question in &message.questions {
        write_name(&mut out, &question.name);
        out.extend_from_slice(&question.qtype.0.to_be_bytes());
        out.extend_from_slice(&question.qclass.to_be_bytes());
    }
    for record in message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
    {
        write_record(&mut out, record);
    }
    out
}

fn write_name(out: &mut Vec<u8>, name: &Name) {
    for label in &name.labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
}

fn write_record(out: &mut Vec<u8>, record: &Record) {
    write_name(out, &record.name);
    out.extend_from_slice(&record.rtype.0.to_be_bytes());
    out.extend_from_slice(&record.class.to_be_bytes());
    out.extend_from_slice(&record.ttl.to_be_bytes());
    out.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&record.rdata);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real query for `example.com A`, built by an independent encoder.
    fn query(id: u16, name: &str, qtype: RecordType) -> Message {
        Message {
            id,
            flags: Flags(0x0100),
            questions: vec![Question::internet(Name::parse(name).expect("name"), qtype)],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    #[test]
    fn a_query_round_trips() {
        let message = query(0x1234, "example.com", RecordType::A);
        let bytes = encode(&message);
        let parsed = parse(&bytes).expect("parses");
        assert_eq!(parsed, message);
        assert!(!parsed.is_response());
        assert!(parsed.flags.recursion_desired());
    }

    #[test]
    fn names_are_case_insensitive_for_comparison_but_preserved_for_encoding() {
        let lower = Name::parse("example.com").expect("name");
        let upper = Name::parse("Example.COM").expect("name");
        assert!(lower.eq_ignore_case(&upper));
        assert_ne!(lower, upper, "case is preserved");
        assert_eq!(upper.to_text(), "Example.COM");
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        let name = Name::parse("a.b.example.com").expect("name");
        assert!(name.ends_with(&Name::parse("example.com").expect("suffix")));
        assert!(name.ends_with(&Name::parse("b.example.com").expect("suffix")));
        assert!(name.ends_with(&name));
        // `ample.com` is not a suffix: the comparison is per label, not per byte.
        assert!(!name.ends_with(&Name::parse("ample.com").expect("suffix")));
        assert!(!name.ends_with(&Name::parse("other.com").expect("suffix")));
        assert!(
            name.ends_with(&Name::root()),
            "the root is everyone's suffix"
        );
    }

    #[test]
    fn a_compressed_name_is_expanded() {
        // Header, one question `a.example.com A`, then an answer whose owner name is a
        // pointer back to offset 12.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7u16.to_be_bytes()); // id
        bytes.extend_from_slice(&0x8180u16.to_be_bytes()); // response, no error
        bytes.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        bytes.extend_from_slice(&1u16.to_be_bytes()); // ancount
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        // question at offset 12
        for label in ["a", "example", "com"] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&1u16.to_be_bytes()); // A
        bytes.extend_from_slice(&1u16.to_be_bytes()); // IN
        // answer: name = pointer to 12
        bytes.extend_from_slice(&[0xc0, 12]);
        bytes.extend_from_slice(&1u16.to_be_bytes()); // A
        bytes.extend_from_slice(&1u16.to_be_bytes()); // IN
        bytes.extend_from_slice(&60u32.to_be_bytes()); // ttl
        bytes.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        bytes.extend_from_slice(&[93, 184, 216, 34]);

        let parsed = parse(&bytes).expect("parses");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name.to_text(), "a.example.com");
        assert_eq!(
            parsed.answers[0].as_ipv4(),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(parsed.answer_addresses().len(), 1);
    }

    #[test]
    fn a_forward_pointer_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // A pointer at offset 12 aiming at offset 14: forward, so a loop.
        bytes.extend_from_slice(&[0xc0, 14]);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), ParseError::BadPointer);
    }

    #[test]
    fn a_self_pointer_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0xc0, 12]); // points at itself
        assert_eq!(parse(&bytes).unwrap_err(), ParseError::BadPointer);
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        // The input is hostile by default: every prefix must fail cleanly.
        let bytes = encode(&query(1, "a.b.c.example.com", RecordType::AAAA));
        for length in 0..bytes.len() {
            let result = parse(&bytes[..length]);
            assert!(result.is_err(), "prefix of {length} bytes must not parse");
        }
        parse(&bytes).expect("the whole message parses");
    }

    #[test]
    fn a_reply_echoes_the_question_and_sets_the_code() {
        let request = query(0x4242, "example.com", RecordType::A);
        let reply = Message::reply_to(&request, ResponseCode::REFUSED);
        assert_eq!(reply.id, request.id);
        assert!(reply.is_response());
        assert_eq!(reply.response_code(), ResponseCode::REFUSED);
        assert_eq!(reply.questions, request.questions);

        let bytes = encode(&reply);
        let parsed = parse(&bytes).expect("parses");
        assert_eq!(parsed.response_code(), ResponseCode::REFUSED);
    }

    #[test]
    fn record_types_parse_from_configuration_spellings() {
        assert_eq!(RecordType::parse("aaaa").expect("parses"), RecordType::AAAA);
        assert_eq!(
            RecordType::parse("HTTPS").expect("parses"),
            RecordType::HTTPS
        );
        assert_eq!(RecordType::parse("65").expect("parses"), RecordType::HTTPS);
        // An unknown mnemonic is an error, not a silently ignored rule.
        assert!(RecordType::parse("BOGUS").is_err());
    }

    #[test]
    fn presentation_names_reject_what_the_wire_rejects() {
        assert!(Name::parse("").is_ok(), "the root");
        assert!(Name::parse("a..b").is_err(), "empty label");
        assert!(Name::parse(&"a".repeat(64)).is_err(), "label over 63");
        let long = vec!["abcdefghij"; 30].join(".");
        assert!(Name::parse(&long).is_err(), "name over 253");
    }
}
