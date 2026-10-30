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
    cargo test -p daer-outbound --test vision_uplink_dump -- --nocapture --include-ignored
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
cargo test -p daer-outbound --test vision_lab -- --nocapture --include-ignored
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
| `tests/vision_lab.rs` | is the Vision frame right, with REALITY out of the path? |
| `tests/reality_live.rs` | does a real node authenticate us and carry bytes, end to end? |
| `tests/reality_tag_audit.rs` | are the ClientHello offsets and groups still as REALITY needs? |
| `tests/client_hello_probe.rs` | is our ClientHello valid TLS at all? (any TLS 1.3 server) |

Run the ignored ones with `-- --include-ignored`.
