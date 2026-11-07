# ADR-0034 — Shadowsocks 2022 and AEAD dual-stack protocol architecture

- Status: accepted
- Date: 2026-11-06
- Related: [ADR-0017](0017-proxy-protocols-crate-boundary.md), [ADR-0028](0028-protocol-layering.md), [ADR-0030](0030-vmess-aead-only.md)
- Scope: [outbound/protocols, protocol/shadowsocks, crypto, config/nodes]

---

## Context

Shadowsocks has evolved across three major eras:
1. **Legacy stream ciphers (pre-2017)**: `aes-256-cfb`, `rc4-md5`, `chacha20`. These lack message authentication (MAC). Active probing and ciphertext bit-flipping attacks allow censors to manipulate packets, observe server RST/FIN reactions, and reliably identify/block proxy endpoints.
2. **Classic AEAD (SIP004 / SIP007, 2017)**: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `xchacha20-ietf-poly1305`. Introduced authenticated framing, but relies on legacy key derivation (`EVP_BytesToKey` with MD5 and `HKDF-SHA1`), lacks server handshake confirmation headers, has fixed-size first-packet fingerprints when payload is empty, and provides loose UDP session management.
3. **Shadowsocks 2022 (SIP022)**: Designed to eliminate active probing vectors and replay vulnerabilities. Key upgrades include:
   - Modern cryptographic primitive: **BLAKE3 key derivation** replaces MD5 and HKDF-SHA1.
   - Pre-Shared Keys (PSK): Directly provided as fixed-length binary keys (base64-encoded); no weak passphrase hashing.
   - Bidirectional timestamp validation (±30s window) and server-echoed request salt verification to prevent replay attacks and probing.
   - Mandatory randomized padding (1..=900 bytes) on empty-payload initial handshakes to eliminate length signatures.
   - Structured UDP datagrams with per-session random client IDs, monotonically increasing packet IDs, and AES-ECB header obfuscation.

Discarding 2017 AEAD would break compatibility with over 90% of current real-world subscription endpoints. Conversely, omitting 2022 leaves `daer` vulnerable to advanced state-level DPI probing where modern servers require SIP022. Legacy stream ciphers, however, are fundamentally broken and remain completely banned per project invariants.

## Decision

### 1. Dual-stack AEAD architecture with strict physical modularity

`daer-proxy-protocols` implements both 2017 AEAD and 2022 AEAD side-by-side, but **isolates them into distinct submodules** (`v1` and `v2`) under `src/shadowsocks/`:
- `src/shadowsocks/v1/`: Classic 2017 AEAD crypto, chunk framing, salt replay filter, and datagram connector.
- `src/shadowsocks/v2/`: SIP022 BLAKE3 KDF, AES-ECB header obfuscator, timestamped framing with padding, echoed salt validator, and session/packet ID datagram connector.
- `src/shadowsocks/link.rs`: Unified SIP002 link parser supporting both legacy base64 credentials and AEAD 2022 plain `method:password` userinfo.
- `src/shadowsocks/connector.rs`: Dispatches cleanly to `v1` or `v2` at connection instantiation time based on the cipher variant.

Cross-version logic is prohibited: no `if is_2022` branching inside inner framing loops or crypto states.

### 2. Supported Cipher Suites

#### Classic AEAD (v1):
- `chacha20-ietf-poly1305`
- `aes-128-gcm`
- `aes-256-gcm`
- `xchacha20-ietf-poly1305`

#### Shadowsocks 2022 (v2):
- `2022-blake3-aes-128-gcm` (16-byte PSK, 16-byte Salt)
- `2022-blake3-aes-256-gcm` (32-byte PSK, 32-byte Salt)
- `2022-blake3-chacha20-poly1305` (32-byte PSK, 32-byte Salt)

Legacy stream ciphers (`aes-128-cfb`, `rc4-md5`, `table`, etc.) continue to be rejected at configuration parse time with actionable errors.

### 3. PSK and Key Derivation Rules

- For 2022 ciphers, `password` MUST be a valid Base64 string that decodes to exactly the cipher's key length (16 or 32 bytes). An invalid key length or invalid Base64 string is rejected at load time.
- Subkey derivation strictly follows SIP022:
  - Context: `"shadowsocks 2022 session subkey"`
  - Key material: `PSK || Salt` (TCP) or `PSK || SessionID` (UDP AES-GCM)
  - Derived key generated via BLAKE3 KDF.

### 4. TCP Wire Framing and Handshake

- **Client Initial Request**:
  - `Salt` (16 or 32 bytes)
  - `Header Chunk`: AEAD-sealed `[Type(0x00)][Timestamp(8B BE)][DataLen(2B BE)]`
  - `First Data Chunk`: AEAD-sealed `[ATYP][Address][Port][PaddingLen(2B BE)][Padding][Payload]`
  - If initial `Payload` is empty, `PaddingLen` MUST be randomly chosen in `1..=900` bytes. If `Payload` is non-empty, `PaddingLen` MAY be 0.
- **Server Response**:
  - `Server Salt` (16 or 32 bytes)
  - `Response Header Chunk`: AEAD-sealed `[Type(0x01)][Timestamp(8B BE)][RequestSalt][DataLen(2B BE)]`
  - Client enforces: `Type == 0x01`, `abs(now - Timestamp) <= 30s`, and `RequestSalt == ClientSalt`.
- **Subsequent Chunks**:
  - `[Length(2B BE)][Tag(16B)][Payload][Tag(16B)]`
  - Nonce increments by 1 per AEAD record.

### 5. UDP Datagrams

- For `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`:
  - 16-byte header: `[SessionID (8B)][PacketID (8B)]` encrypted with PSK using AES-ECB.
  - AEAD Nonce: bytes 4..16 of the plaintext header.
  - Subkey: derived from `PSK || SessionID`.
  - Body: AEAD-sealed `[Type][Timestamp][PaddingLen][Padding][Address][Payload]`.
- For `2022-blake3-chacha20-poly1305`:
  - 24-byte random nonce followed by AEAD-sealed payload using PSK.

## Consequences

- `blake3` is added to workspace dependencies.
- `crates/daer-proxy-protocols` fully isolates `v1` and `v2` implementations.
- `daer-config` strictly validates Base64 PSKs for 2022 methods at startup.
- Full interoperability with reference `shadowsocks-rust` and modern proxy ecosystems.
