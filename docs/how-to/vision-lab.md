# The Vision lab: a local `xray run` to debug against

REALITY and Vision both fail *silently*, and their failures are indistinguishable from a
working connection at the API level:

* a REALITY tag the node cannot open makes it **forward** the flow to the impersonated site,
  so the client completes a valid TLS handshake against a host nobody asked for;
* a Vision block the peer does not recognise is treated as **payload**, so a framing mistake
  corrupts the stream instead of erroring.

Against a remote node neither is observable — the peer says nothing either way. A local
`xray run` with `"show": true` and `loglevel: debug` says everything: it prints the REALITY
verdict (`hs.c.conn == conn: true`), the client version it read, and every Vision block it
unpadded.

This is what found the last three defects:

```text
REALITY remoteAddr: 127.0.0.1:49498  hs.handshake() err: <nil>
from 127.0.0.1:49498 accepted tcp:[b65:7861:6d70:6c65:2e63:6f6d:50:4]:80 [direct]
                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                    garbage address: the VLESS port was written twice
```

```text
proxy/vless/inbound: firstLen = 52
                                    ^^^^^^^^^^^^^
                                    header arrived without the Vision block, so the
                                    inbound had no block to unpad
```

```text
proxy: Xtls Unpadding new block, content 56 padding 37 command 0
                                    ^^^^^^^^^ correct content, wrong command:
                                    `Continue` where the payload must say `End`
```

## Building the server

`Xray-core` is a sibling checkout. Go 1.27 is what it wants; a mirror is needed when the
default proxy is unreachable.

```sh
cd ../Xray-core
GOPROXY=https://goproxy.cn,direct go build -o /tmp/xray ./main
/tmp/xray x25519          # -> PrivateKey / Password(PublicKey)
```

## REALITY on a local port

```json
{
  "log": { "loglevel": "debug" },
  "inbounds": [{
    "listen": "127.0.0.1", "port": 18443, "protocol": "vless",
    "settings": {
      "clients": [{ "id": "<uuid>", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": {
        "show": true,
        "dest": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "privateKey": "<PrivateKey>",
        "shortIds": ["ef37119567cd97"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

Then:

```sh
setsid /tmp/xray run -c server.json > /tmp/lab/reality.log 2>&1 < /dev/null &
DAER_REALITY_LINK='vless://<uuid>@127.0.0.1:18443?encryption=none&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=<PublicKey>&sid=ef37119567cd97&type=tcp&fp=chrome#lab' \
    cargo test -p daer-proxy-protocols --test vision_uplink_dump -- --nocapture --include-ignored
```

`dest` must be a **real** site on 443. REALITY mimics the target's handshake record lengths,
and a local `openssl s_server` produces certificates too small for that: the node then fails
with `hs.handshake() err: payload[0]: 8, padding: -4`, which is about *its own* record
padding and has nothing to do with the client.

## Vision without REALITY

To rule REALITY out entirely, give the inbound `security: tls` with a self-signed
certificate and run `tests/vision_lab.rs`, which speaks TLS itself and hand-builds the
frames:

```json
"tlsSettings": {
  "alpn": ["http/1.1"],
  "certificates": [{ "certificateFile": "cert.pem", "keyFile": "key.pem" }]
}
```

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout key.pem -out cert.pem -days 2 -nodes -subj /CN=apple.com
cargo test -p daer-proxy-protocols --test vision_lab -- --nocapture --include-ignored
```

Use an **ECDSA** certificate: `rustls` offers a narrow signature-algorithm list and the
inbound answers `tls: peer doesn't support any of the certificate's signature algorithms`
for an RSA one.

A working exchange logs exactly this shape, and it is what the writer is asserted against:

```text
Xtls Unpadding new block, content 0  padding 900 command 0
Xtls Unpadding new block, content 56 padding 0   command 1
```

## What each test is for

| Test | Answers |
| --- | --- |
| `tests/e2e/protocols_reality_interop.rs` | **CI's gate**: start a local reference `xray` inbound and carry bytes both ways through REALITY + Vision. Skips with a reason without `xray`. Carries the negative controls (a wrong `pbk`, a non-REALITY server) |
| `tests/vision_lab.rs` | is the Vision frame right, with REALITY out of the path? |
| `tests/reality_live.rs` | does a *third-party* node authenticate us and carry bytes, end to end? Needs `DAER_REALITY_LINK`; not a CI gate, because a public node is someone else's uptime and someone else's config |
| `tests/reality_tag_audit.rs` | are the ClientHello offsets and groups still as REALITY needs? |
| `tests/client_hello_probe.rs` | is our ClientHello valid TLS at all? (any TLS 1.3 server) |

Run the ignored ones with `-- --include-ignored`.

## The interop test starts its own server

`tests/e2e/protocols_reality_interop.rs` is the one to run before touching the REALITY or Vision paths, and
the one CI relies on. It needs no configuration and no credential:

```sh
cargo test -p daer-proxy-protocols --test reality_interop -- --nocapture
XRAY_BIN=../Xray-core/xray cargo test -p daer-proxy-protocols --test reality_interop
```

It generates a key pair with `xray x25519`, starts a REALITY inbound on a free port **and its own
TLS 1.3 impersonation target** from `tests/fixtures/` (a seven-certificate
chain, so the handshake has the record lengths REALITY needs to mimic), points the node's
`freedom` outbound at a local HTTP origin, and asserts that the origin's body comes back through
the tunnel: `Content-Length`, then the exact bytes. Then it asserts the *two* negations that make
that assertion mean something: a wrong `pbk` must be refused rather than forwarded, and a server
that speaks no REALITY must not be accepted. Without those, a client that accepted any TLS server
would pass.

Everything is local, so the gate is deterministic: it used to point `dest` at
`www.microsoft.com:443` and ask the node to reach `example.com:80`, which made the one test able
to catch a REALITY regression depend on two third parties.

Two fixture details are load-bearing and were both wrong at first:

- the local TLS target must present a **realistically large** chain. REALITY mimics the
  destination's handshake record lengths, and a small certificate makes the **node** fail its own
  padding check (`payload[0]: 8, padding: -4`), which reads like a client bug;
- since Xray v26.4.15 a `freedom` outbound blocks private and reserved destinations by default
  for flows that arrived through a proxy inbound, and **blackholes** them for 30-90 s. A local
  origin is a private address, so the node answers `blocked target: … blackholing connection` and
  the client sees an empty reply — indistinguishable from a broken tunnel. The fixture grants
  `finalRules: [{action: allow, ip: ["127.0.0.0/8"]}]`; a production node must not.

`DAER_REALITY_DEST` overrides the impersonated site with a real one instead
(`DAER_REALITY_DEST=www.microsoft.com:443`), and `DAER_REALITY_SNI` names the SNI when the
destination is an address rather than a hostname.
