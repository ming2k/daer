# Test-only TLS fixtures

`reality_dest_chain.pem` / `reality_dest_key.pem` are a throwaway certificate chain for
`tests/reality_interop.rs`: they stand in for the site a REALITY node impersonates, so the
interop gate runs offline and deterministically instead of depending on `www.microsoft.com`.

**They are test material. They grant nothing and must never be installed anywhere.** The private
key is in the clear, on purpose — a test fixture nobody can read is a test fixture nobody can
fix. Nothing in `daer` trusts this chain; the client never validates the impersonated site's
certificate (REALITY replaces the authentication with its own tag), and the chain exists only so
the *reference xray* server has a handshake to answer with.

# Why seven certificates

REALITY mimics the record lengths of the destination's handshake, and the node checks the
padding it produces against what it saved from the destination. A too-small certificate makes
the **node** fail its own check (`payload[0]: 8, padding: -4`), which reads like a client bug.
A leaf plus five intermediates plus a root produces a 4.5 KB chain — ServerHello 1215 bytes,
Certificate 3076 bytes — which is the shape a real site produces. Shrinking this chain will
break the interop test in a way that blames the wrong component.

# Regenerating

```sh
# RSA would also work; ECDSA P-256 keeps the file small while the chain keeps the total large.
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.pem \
    -subj "/CN=daer Test Root CA" -addext "basicConstraints=critical,CA:TRUE"
# then five intermediates chained off the root, then a leaf for reality-interop.test
```

The leaf's `subjectAltName` must contain `reality-interop.test`: that is `DEST_SNI` in
`tests/reality_interop.rs`, and REALITY authenticates the name in the ClientHello.
