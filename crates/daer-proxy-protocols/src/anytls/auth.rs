// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS client authentication.
//!
//! Upon establishing a TLS session with an AnyTLS server, the client immediately sends
//! an authentication flight before any multiplexed frames:
//! ```text
//! +----------------------------+-----------------------+-----------------------+
//! |  SHA256(password) (32 B)   |   padding0_len (2 B)  |  padding0 (variable)  |
//! +----------------------------+-----------------------+-----------------------+
//! ```
//! The padding bytes are discarded by the server and serve to disrupt size-based traffic
//! analysis of the initial post-TLS handshake bytes.

use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Calculates SHA256 of the AnyTLS password.
#[must_use]
pub fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Constructs the initial authentication flight bytes.
#[must_use]
pub fn make_auth_flight(password: &str, padding_len: u16) -> Vec<u8> {
    let hash = hash_password(password);
    let mut out = Vec::with_capacity(32 + 2 + padding_len as usize);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&padding_len.to_be_bytes());
    if padding_len > 0 {
        // Deterministic zero padding for now, obfuscating initial record length
        out.resize(32 + 2 + padding_len as usize, 0);
    }
    out
}

/// Sends authentication flight over `writer` and flushes.
pub async fn send_authentication<W: AsyncWrite + Unpin>(
    writer: &mut W,
    password: &str,
    padding_len: u16,
) -> Result<(), std::io::Error> {
    let flight = make_auth_flight(password, padding_len);
    writer.write_all(&flight).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_auth_flight_structure() {
        let password = "my-secret-password";
        let hash = hash_password(password);
        assert_ne!(hash, [0u8; 32]);

        let flight = make_auth_flight(password, 16);
        assert_eq!(flight.len(), 32 + 2 + 16);
        assert_eq!(&flight[..32], &hash);
        assert_eq!(&flight[32..34], &16u16.to_be_bytes());
        assert_eq!(&flight[34..], &[0u8; 16]);

        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            send_authentication(&mut client, password, 8).await.unwrap();
        });

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), 32 + 2 + 8);
        assert_eq!(&received[..32], &hash);
    }
}
