// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks cipher definitions, identifiers, and protocol error types.

use std::fmt;

/// The AEAD ciphers supported by daer (2017 AEAD & 2022 AEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    // 2017 AEAD (SIP004 / SIP007)
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,

    // Shadowsocks 2022 (SIP022)
    Aead2022Blake3Aes128Gcm,
    Aead2022Blake3Aes256Gcm,
    Aead2022Blake3ChaCha20Poly1305,
}

impl Cipher {
    /// Parses a cipher name as it appears in a `ss://` link or configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`CipherError::Unsupported`] for a recognised-but-rejected legacy cipher, and
    /// [`CipherError::Unknown`] for an unknown name.
    pub fn parse(name: &str) -> Result<Self, CipherError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "xchacha20-ietf-poly1305" => Ok(Self::XChaCha20Poly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Aead2022Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aead2022Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Aead2022Blake3ChaCha20Poly1305),
            legacy @ ("aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb" | "aes-128-ctr"
            | "aes-192-ctr" | "aes-256-ctr" | "rc4-md5" | "chacha20"
            | "chacha20-ietf" | "salsa20" | "bf-cfb" | "camellia-128-cfb"
            | "camellia-192-cfb" | "camellia-256-cfb" | "des-cfb" | "table") => {
                Err(CipherError::Unsupported(legacy.to_owned()))
            }
            other => Err(CipherError::Unknown(other.to_owned())),
        }
    }

    /// The canonical cipher name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-ietf-poly1305",
            Self::XChaCha20Poly1305 => "xchacha20-ietf-poly1305",
            Self::Aead2022Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aead2022Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Aead2022Blake3ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// True when this cipher belongs to Shadowsocks 2022 (SIP022).
    #[inline]
    #[must_use]
    pub const fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Aead2022Blake3Aes128Gcm
                | Self::Aead2022Blake3Aes256Gcm
                | Self::Aead2022Blake3ChaCha20Poly1305
        )
    }

    /// Key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aead2022Blake3Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::XChaCha20Poly1305
            | Self::Aead2022Blake3Aes256Gcm
            | Self::Aead2022Blake3ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes.
    #[must_use]
    pub const fn salt_len(self) -> usize {
        self.key_len()
    }

    /// Tag length in bytes (16 for all supported AEAD modes).
    #[must_use]
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Nonce length.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }

    /// Maximum payload carried per record.
    #[must_use]
    pub const fn max_payload(self) -> usize {
        if self.is_2022() { 0xFFFF } else { 0x3FFF }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a cipher name was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// A legacy cipher with no integrity protection.
    Unsupported(String),
    /// A name this build does not know.
    Unknown(String),
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => write!(
                f,
                "shadowsocks cipher {name:?} is not supported: it has no authentication, so \
                 traffic could be modified in transit. Use an AEAD cipher \
                 (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-128-gcm) instead"
            ),
            Self::Unknown(name) => write!(f, "unknown shadowsocks cipher {name:?}"),
        }
    }
}

impl std::error::Error for CipherError {}

/// A decryption failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptError;

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("shadowsocks record failed authentication")
    }
}

impl std::error::Error for DecryptError {}

/// Why a shadowsocks stream failed.
#[derive(Debug)]
pub enum ShadowSocksError {
    /// The AEAD record did not authenticate: the key, the salt or the bytes are wrong.
    Crypto(DecryptError),
    /// The underlying transport failed.
    Io(std::io::Error),
    /// The peer's salt repeats one already seen on this stream.
    Replay,
}

impl fmt::Display for ShadowSocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(f, "shadowsocks: {error}"),
            Self::Io(error) => write!(f, "shadowsocks transport: {error}"),
            Self::Replay => f.write_str("shadowsocks: repeated salt (possible replay)"),
        }
    }
}

impl std::error::Error for ShadowSocksError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Replay => None,
        }
    }
}

impl From<std::io::Error> for ShadowSocksError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DecryptError> for ShadowSocksError {
    fn from(error: DecryptError) -> Self {
        Self::Crypto(error)
    }
}

impl From<ShadowSocksError> for std::io::Error {
    fn from(error: ShadowSocksError) -> Self {
        match error {
            ShadowSocksError::Io(error) => error,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}
