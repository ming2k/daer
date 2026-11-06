// SPDX-License-Identifier: AGPL-3.0-only

//! VMess AEAD (ADR-0030).
//!
//! # Why only AEAD
//!
//! The legacy VMess handshake authenticates with a key derived from the user's UUID alone, so a
//! captured first packet is replayable forever. The AEAD format replaced it, and a modern
//! server refuses legacy clients. Implementing both would add an attack surface daer gains
//! nothing from and would not connect to anything current, so the legacy path is not
//! expressible: `daer-config` has no key that selects it, and a link whose `aid` (alterId) is
//! non-zero is a load error naming that reason.
//!
//! # The layers
//!
//! VMess is a protocol in ADR-0028's sense: a security layer and a transport layer underneath,
//! a chunk-framed byte stream (or datagram stream) above.
//!
//! | Module | Owns |
//! | --- | --- |
//! | [`kdf`] | the reference's nested-HMAC KDF, and the user's `cmdKey` |
//! | [`aead`] | `AuthID`, the sealed request header, and the CRC/FNV checksums |
//! | [`header`] | the plaintext request and response header layouts |
//! | [`chunk`] | the AEAD chunk stream, SHAKE-128 size masking and padding |
//! | [`connector`] | the composition, and the two planes |

pub mod aead;
pub mod chunk;
pub mod connector;
pub mod header;
pub mod kdf;
pub mod response;
pub mod stream;

pub use connector::VmessConnector;
