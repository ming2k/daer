# Diagnostics

Where to look, in the order you will need it. Every claim here is enforced by a
test or by a field name that exists in the code — this page is a map, not
aspiration.

## 1. "What is running?"

```
info  configuration loaded      generation=gen1 rules=6 groups=2 nodes=8 build_ms=3
info  configuration reloaded    generation=gen2 previous=gen1 rules=7 groups=2 nodes=8 routing_changed=true build_ms=2
```

* `generation` is monotonically increasing. Identifiers count **attempts**: a
  rejected reload still consumes one, so `gen4 rejected` can never be confused with
  `gen4 serving`.
* `routing_changed` compares the **semantic hash** of the compiled routing policy,
  not the file. `false` means the configuration was rewritten but traffic goes the
  same way — which is exactly when the kernel side has nothing to rewrite.

Inspect without a log pipeline:

```rust
let generations = Generations::new(&config)?;
let current = generations.current();          // Arc<Generation>, pinned for a flow
current.describe();                            // "gen1 rules=6 groups=2 nodes=8 built_in=3ms"
current.policy_hash();                         // [u8; 32]
```

## 2. "The reload failed."

```
error configuration reload rejected; the running generation is unchanged
      generation=gen5 serving=gen4 error=outbound (group) "nope" not found …
```

A rejected generation publishes nothing: `Generations::reload` returns
`ReloadError { source, serving }`, and `serving` names the generation that is still
answering. There is no rollback step because there is nothing to roll back — the
build happens before the swap.

The `Display` of the error says both facts, because a reload failure that leaves
the proxy serving is not an outage and must not read like one:

```
reload rejected: outbound (group) "nope" not found; gen4 is still serving
```

## 3. "This flow went to the wrong outbound."

```
debug flow decided   generation=gen2 source=192.168.1.10:41234 destination=93.184.216.34:443
                     rule=rule 0 outbound=block mark=0 must=false
```

`rule` is the index of the matching rule in the compiled program, or `fallback`
when nothing matched. That is the whole answer to "why": a rule number and the
generation that contained it. `mark` and `must` are part of the log because they
change what the kernel and the outbound do, and reading them from the log is faster
than reading the config.

```
trace node selected  group=proxy node=hk-01 protocol=Socks5
debug flow closed    destination=93.184.216.34:443 to_upstream=512 to_client=4096 elapsed_ms=87
```

An empty relay (`to_upstream=0 to_client=0`) is a probe or a failed dial, not a
session: it is worth reporting separately downstream.

### Reproduce it offline

```sh
daer route explain 192.168.1.10:41234 93.184.216.34:443 -c config.toml
```

```
192.168.1.10:41234 → 93.184.216.34:443  [gen1]
  decided by : !domain(suffix: internal.example) && port(443) -> proxy
  outbound   : proxy (mark 0)
```

It compiles the same generation a running daer would use and asks it the same
question, so the answer is the answer the data path acts on — no kernel, no
privileges, no traffic. The exit status is part of the contract: `0` when the flow
has a usable outbound, `1` when it would be dropped (`block`, a missing group, an
empty group) or when the configuration cannot run at all. A diagnostic that always
exits 0 cannot be used in a check.

The `decided by` line is the **normalized** rule, not the file's spelling: the
optimizer rewrites `dport` to `port`, sorts parameters and merges adjacent rules.
Showing the raw input would risk displaying a rule the engine never evaluated.

A `domain(...)` rule cannot fire without a name, and the data path gets that name
from sniffing. `--domain <name>` supplies the same fact from the command line, which
is the only way to verify a domain rule without a live flow:

```
daer route explain 10.0.0.2:40000 93.184.216.34:443 -c config.toml --domain www.bilibili.com
```

From code, the same answer is available as data:

```rust
let explanation = router.explain(source, destination)?;
assert_eq!(explanation.rule, Some(0));
assert_eq!(explanation.outbound.name, "proxy");
```

### "Why did the rule I wrote never fire?"

```sh
daer route explain 192.168.1.10:41234 93.184.216.34:443 --why -c config.toml
```

```
192.168.1.10:41234 → 93.184.216.34:443  [gen1]
  decided by : !domain(suffix: internal.example) && port(443) -> proxy
  outbound   : proxy (mark 0)

rule 0 [skipped]
  x dip(10.0.0.0/8)
  -> dip(10.0.0.0/8) did not match
rule 1 [fired]
  v !domain(suffix: internal.example)
  v port(443)
```

Three statuses, and the distinction between the last two is the usual answer to a
surprise:

| Status | Meaning |
| --- | --- |
| `fired` | this rule decided |
| `skipped` | a predicate did not hold; the offending one is named |
| `shadowed` | every predicate held, but an earlier rule decided first |

`shadowed` is why a rule can look correct and never apply: rules are evaluated in
order, and `--why` prints the shadowed ones explicitly rather than leaving it to be
inferred.

Two properties make this trustworthy rather than plausible:

* **The trace and the verdict cannot disagree.** Both are derived from one
  evaluation, and the trace carries the *effective* outbound — including the fallback
  when no rule matched. Asserted by `the_trace_and_the_verdict_never_disagree`.
* **Predicates are grouped the way the configuration nests them.** `port(80, 8080)`
  is one predicate with two values, not two predicates; two functions in one rule are
  two predicates. Both groupings have tests, because a report that misgroups
  predicates sends you to the wrong line.

or just the verdict, when the rule text is not needed:

```rust
let verdict = router.verdict_for(source, destination);
assert_eq!(verdict.describe(), "rule 0");
```

These are the intended ways to turn a bug report ("this host went through the
proxy") into a regression test.

### Rule numbers are rule ordinals

`rule 0` is the first rule in the configuration, not the first internal match set.
One rule lowers to several match sets (one per predicate), so an internal index
would be a number no operator can map back to their file. The ordinal is
`NormalizedProgram::rules[n]`, and `route explain` prints that rule's text so the
number never has to be looked up by hand.

### Facts the ingress does not have

A redirected TCP flow supplies addresses, ports and `TCP`. The sniffed domain, the
client's process name, DSCP and the source MAC live in the kernel's connection
state and are **not** available to the ingress yet. They are passed as unknown
(`domain = None`, `process_name` unspecified, `dscp = 0`, zero MAC), which means:

> a rule that depends on them cannot match on the ingress path.

That is a correctness property, not a limitation to work around: a guessed domain
would silently route traffic through the wrong outbound. `daer-sniff` and the state
map are what fill them in, and until then the honest answer is "this rule never
fires here" — visible as a rule that never appears in `flow decided` logs.

## 4. "Traffic is not being served at all."

| Symptom | Look at | Meaning |
| --- | --- | --- |
| `debug dropped a flow that was not redirected` | `Reject::SelfConnect` | a client connected to the transparent port directly; nothing to route |
| `debug blocked by a routing rule` | `Reject::Blocked` | a rule said `block`; the flow was dropped on purpose |
| `debug no outbound leg` | `IngressError::Dial` | the group had no selectable node, or the dial failed |
| `warn accept failed on a resource limit; backing off` | `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` | fd or memory pressure; the loop backs off and keeps serving |
| `warn a flow task failed` | a panicked flow | isolated to that flow; `panicked` in the counters |

Counters name the magnitude of each of those:

```rust
let stats = metrics.snapshot();
// ServeStats { accepted, rejected, failed, exhausted, panicked }
```

`failed` includes both "no selectable node" and "dial failed"; the log line tells
them apart.

## 5. "The configuration is wrong."

The configuration layer reports before anything runs:

* `daer config validate` — loads the tree (including `include`), applies defaults,
  compiles every rule, resolves every outbound name, and dry-runs groups and
  filters. Errors carry `line:column` and a caret, including inside a rule
  expression.
* `daer config schema` — the JSON Schema, so an editor flags a typo before the
  validator ever runs. Automated test `schema_is_up_to_date` fails if the checked-in schema drifts
  from the model.

```
invalid expression "domain(a) direct"
line 1:10 domain(a) direct
              ^: expected '->' in the routing rule
```

## 5b. "Did the reload disturb traffic?"

```
info  stopped accepting; live flows keep relaying  in_flight=3
```

A reload stops *accepting*, never *relaying*. The flows a loop spawned are owned by
the supervisor, so the loop returning says nothing about them; `in_flight` is the
number that survived. A reload with live connections can be verified before it is
allowed to finish:

```rust
supervisor.drain().await;   // waits for the flows the old generation started
```

`drain` is safe to call from several tasks at once: it registers for the wakeup
before reading the counter, and the last flow broadcasts, so a second waiter cannot
be stranded.

What the test suite asserts (`tests/handover.rs`):

| Property | Test |
| --- | --- |
| a mid-transfer flow survives a reload | `a_live_flow_survives_a_reload` |
| the port is never unbound | `the_port_stays_up_across_a_handover` |
| one connection crosses 8 generations | `one_connection_crosses_many_generations` |
| stopping a loop does not reset the service | `stopping_a_loop_does_not_reset_the_service` |

## 5c. "Why did this query go to that upstream?"

DNS has its own routing, and its failures look different from IP routing's:

| Symptom | Cause | Where it is caught |
| --- | --- | --- |
| `upstream "remtoe" not found` | the rule names a tag `dns.upstream` does not declare | load time, not per query |
| `dport() is not a selector this block understands (dns.request)` | an IP-routing predicate used in a DNS block | load time, with the block named |
| a query with no single question got the fallback | a request can only be routed by name when it has exactly one question | `RequestRouter::decide` |
| `asis` behaves like a direct answer, not a forward | `asis` is a decision, not an upstream | `Decision::AsIs` |
| a response rule never fires | it needs `[dns.response]`, not `[dns.request]`; address and upstream selectors exist only there | `ResponseRouter::compile` |

The request/response split is a compile-time distinction, not a convention: request
selectors are `qname`/`qtype`, response selectors add `ip`/`upstream`, and using one in
the wrong block is an error naming the block.

### "Is this answer from the cache, and is it stale?"

The cache returns one of two things, and the difference is visible in the value rather
than inferred:

| Variant | Meaning | What to do |
| --- | --- | --- |
| `Cached::Fresh { ttl }` | still valid; `ttl` is the **remaining** time, not the original | serve it |
| `Cached::Stale { ttl, expired_for }` | expired but inside the stale window; `ttl` is the short stale TTL | serve it **and** refresh in the background |

`needs_refresh()` is the single call that decides whether a refresh is owed, and
`expired_for` is what a log line should carry. Three behaviours that surprise people, and
are therefore explicit:

* a `fixed-domain-ttl` override replaces the record TTL, and the **longest suffix wins** —
  this is a property of `Cache::new`, not of the caller, so a hand-built `CacheConfig`
  cannot get it wrong;
* the stored TTL is the **minimum** across the answer's records, because a cache may not
  outlive any record it serves;
* `NXDOMAIN` and NODATA are cached (those are the lookups worth caching), `SERVFAIL` is
  not (it carries nothing to remember), and a TTL of 0 is never cached.

## 5d. "Is the resolver doing what I think?"

One structured line per query at `debug`, two at `trace`:

```
debug dns request routed   question=example.com A       decision=local
debug dns stale answer served; a refresh is owed        question=… expired_for_ms=12000
debug dns answer routed    question=example.com A       upstream=local action=accept elapsed_ms=4
```

The counters answer "how much", and every one of them has exactly one meaning:

| Counter | Incremented when |
| --- | --- |
| `hits` | a fresh cache hit was served |
| `stale_hits` | an expired-but-in-window hit was served, so a refresh is owed |
| `misses` | a lookup found nothing usable — counted **at the cache**, not at the upstream |
| `upstream_calls` | an exchange was attempted, failovers included |
| `upstream_errors` | an exchange failed |
| `rejects` | a rule answered `REFUSED` |
| `as_is` | the query was handed back to the client's resolver |
| `failovers` | a `[dns.response]` rule sent the answer to a second upstream |

`hit_ratio()` is `(hits + stale_hits) / (hits + stale_hits + misses)` and is `None` before
the first lookup, because a ratio with no denominator is not zero, it is unknown.

Three outcomes that must not be confused, and are not:

* **`REFUSED`** — a rule said `reject`. An answer, deliberately.
* **`SERVFAIL`** — the upstream failed, or no transport is registered for that tag. Also
  an answer: a client that gets nothing retries and holds its slot.
* **`Resolution::AsIs`** — not ours to answer. The caller must **not** turn this into a
  refusal; `asis` means "let the client's own resolver do it".

## 5e. "Why was this flow not routed by domain?"

Sniffing returns a decision, and the decision is the answer:

| `Sniffed` | Meaning | What to do |
| --- | --- | --- |
| `NeedMore { want }` | a plausible prefix, name not complete | read more; `want` is the smallest useful total |
| `Domain { name, protocol }` | routed by name from here | feed it into the routing facts |
| `None` | nothing nameable in these bytes | route by IP; do not keep reading |
| `Malformed(reason)` | the bytes contradict themselves | stop, route by IP, and log the reason |

The cases that look like bugs and are not:

* **QUIC always returns `None`.** A QUIC Initial is encrypted; recovering the SNI needs
  header-protection removal and TLS reassembly, which is not implemented. A "clever"
  approximation would report wrong names, which is worse than routing by IP.
* **TLS with ECH returns `None`.** Encrypted ClientHello hides the name from a proxy by
  design; reporting the outer name as the inner one would be a lie.
* **A ClientHello split across records still works.** Fragments are concatenated before
  the handshake body is read, which is how a large hello actually arrives.
* **`Forwarded` / `X-Forwarded-Host` are ignored.** They are set by intermediaries. Only
  `Host` (or an absolute-form request target) names the origin the client asked for.
* **A flow whose configuration has no `domain(...)` rule is never sniffed.** The decision
  is made once per generation, so there is no syscall and no wait on such a flow. If you
  add a domain rule and still see no sniffing, the rule is not a `domain` one.
* **The stream is peeked, not consumed.** After a sniff the origin still receives exactly
  what the client sent; a byte count mismatch at the origin is not a sniffing artefact.

## 5f. "Which upstream is actually being used?"

`dns.upstream` entries are `tag:protocol://host:port`, and the tag is what rules refer to.
Two failures look like configuration mistakes and are not:

| Message | Meaning |
| --- | --- |
| `no transport for google (udp)` | the entry parsed; this build cannot speak that protocol yet |
| `dns.upstream entry "nonsense" has no tag` | the entry itself is malformed — this fails the build, not a query |
| `tag "asis" / "reject" is reserved` | those are decisions, not upstreams; renaming the tag fixes it |
| `"dns.google" is not ip:port (name resolution for upstreams is not implemented yet)` | bootstrapping an upstream by name is a resolver problem of its own |

A TCP exchange has four observable failure modes, each with a distinct message: connect
failed, write failed, no answer within the timeout, or a reply that is malformed / carries
someone else's id. The id check matters: accepting a mismatched reply would serve one
client the answer to another client's question.

## 5g. "The client got no answer, or a wrong one"

The server has exactly three ways to answer and one way to stay silent, and each is a
decision the configuration made:

| Client sees | Meaning |
| --- | --- |
| an answer | normal |
| `REFUSED` | a `[dns.request]`/`[dns.response]` rule said `reject` |
| `SERVFAIL` | the upstream failed, no transport is registered, or the answer took longer than the request timeout |
| `TC` set, no answers | the answer did not fit the client's UDP size; retry over TCP |
| **nothing** | `asis`: the client's own resolver is supposed to answer. Not an error |

Two details that look like bugs and are correctness:

* **A too-large UDP answer is truncated with `TC`, never silently shortened.** A shortened
  answer parses as a valid but wrong answer, which is worse than asking the client to retry.
* **The advertised EDNS size is honoured between 512 and 4096.** Above that the reply would
  fragment, and fragments on DNS are a reliability problem.

## 5h. "Is the resolver running correctly?"

Two commands and one log line answer it without a packet capture:

```sh
daer dns check -c config.toml
```

```
plain [tcp] ok
remote [udp] unusable: no transport for upstream "remote"
1 of 2 upstream(s) cannot be used by this build
```

`check` exits non-zero for any unusable upstream, so it works as a gate. It compiles the
full resolver before reporting, so it cannot pass a configuration `serve` would refuse.

```sh
daer dns serve -c config.toml
```

```
daer dns: serving 0.0.0.0:53 on udp+tcp
```

`dns.bind` is an **IP**, not an address: the port is always 53. `--listen` takes a full
`ip:port` and overrides it. A port inside `dns.bind` is rejected with the field name rather
than silently interpreted, because "bind 127.0.0.1:5353" and "bind 127.0.0.1" differ by
something the operator cannot see in the file.

## 5i. "The shadowsocks node does not work"

| Message | Meaning |
| --- | --- |
| `cipher "aes-256-cfb" is not supported: it has no authentication …` | the link uses a stream cipher. Use an AEAD cipher; the refusal is deliberate |
| `credentials are not \`method:password\`` | the base64 payload is malformed |
| `link has an empty password` | the link parses but has no secret |
| `shadowsocks record failed authentication` | the key, the salt or the bytes are wrong — the message deliberately does not say which |
| the node is listed but `no selectable node` | the link was rejected at generation build; see the log line naming the reason |

Two failure modes that are protocol-level, not configuration-level:

* **A wrong password looks like a reset connection.** The server cannot decrypt the address
  frame, so it closes. The client reports a transport failure because that is all it can see.
* **A repeated salt is refused, but only within one process.** The replay filter is bounded and
  in memory; a restart forgets it. That is stated rather than implied.

## 5j. "The trojan node does not connect"

| Message | Meaning |
| --- | --- |
| `needs \`?sni=…\`: a TLS certificate cannot be verified against the bare address 1.2.3.4` | the link points at an IP with no `sni`. Name the certificate's host; do not disable verification |
| a TLS error mentioning the certificate | the node's certificate did not verify. Trojan nodes are fronted by a real certificate; a self-signed one is refused rather than trusted |
| `connect` failure | the node is unreachable, or the TLS handshake never completed |
| the node is listed but not selectable | the link failed to parse at generation build; the log line names the reason |

Three things that are protocol-level rather than configuration-level:

* **Trojan has no encryption of its own.** The session is protected by TLS and by nothing
  else, which is why a plaintext path does not exist in the code at all.
* **A password mismatch is invisible until the tunnel is used.** Trojan has no error reply:
  the server simply proxies, or a fronting web server answers with HTTP. The client reports a
  handshake or transport failure because that is all it can observe.
* **Unknown query parameters are ignored.** Panels add `type=ws`, `host=`, `path=` and others
  freely; rejecting them would lock an operator out of their own subscription for a reason
  that does not affect the connection.

## 5k. "Which nodes exist, and how is each session protected?"

```sh
daer route nodes -c config.toml
```

```
[proxy]
  hk-ss [ss | cipher aes-256-gcm]
  jp-trojan [trojan | tls sni=jp.example.com]
  lan [socks5 | plaintext]

1 of 3 node(s) carry no confidentiality: socks5/http send credentials in plain text, and
`direct` is by definition unencrypted
```

The security identity is derived **structurally** — from the scheme, the cipher name and the
`sni` parameter, never from a password, key or certificate. That is a design constraint, not a
convention: a diagnostic that printed a credential would turn a bug report into a credential
leak, so `Property::security` cannot reach one.

`route explain` carries the same identity for the node a rule selected, so one command answers
"which rule, which outbound, which node, and how is it protected":

```
10.0.0.5:40000 → 93.184.216.34:443  [gen1]
  decided by : port(443) -> proxy
  outbound   : proxy (mark 0)
  node       : proxy: hk-ss [ss | cipher aes-256-gcm]
```

Three values that surprise people, and are therefore explicit:

| Value | Meaning |
| --- | --- |
| `plaintext` | socks5/http: credentials, if any, are on the wire |
| `cipher aes-256-cfb (unauthenticated, rejected)` | the link names a stream cipher; it is refused, and the listing says why |
| `tls sni=… (allowInsecure ignored)` | the link asked to skip verification; this build does not do that |

`is_confidential()` is the one call a caller should use to decide whether a node protects the
session, so a new protocol cannot be added without deciding which it is.

## 5l. "Did the kernel actually switch generations?"

The userland answer is in the reload log (`generation=gen2 previous=gen1 routing_changed=true`).
The kernel answer is the active routing slot, and the two can disagree only if a commit failed —
which is why that failure is reported as its own case rather than folded into "write failed".

What is checkable without privileges:

| Question | Where |
| --- | --- |
| is every map classified as per-generation or shared? | `daer-ebpf::names::generationality`; an unclassified map fails a test |
| can a failed publish ever move the active slot? | `daer-ebpf::epoch` — asserted for a mid-batch `ENOMEM`, a bad stamp, and a failed commit |
| can a packet see half a table? | by construction: it is written to the slot nobody is reading, then committed with one switch |
| is generation 0 a valid id? | no; it is the "never published" sentinel, and passing it panics rather than publishing a table the datapath must ignore |

The last one matters more than it looks: the kernel treats an unknown or unpublished slot as
"pass through", so a bug that published under generation 0 would produce a proxy that silently
routes nothing.

## 6. What each layer promises

| Layer | Promises |
| --- | --- |
| `inbound` | a socket option it cannot set is an error, never a warning; the destination is the kernel's, never guessed |
| `decide` | everything statically checkable is checked at generation build, not per flow; an unknown protocol is never downgraded to `direct` |
| `relay` | EOF is forwarded, not connection teardown; byte counts are per direction |
| `serve` | one broken flow never ends the loop; resource exhaustion backs off; a flow is owned by the supervisor, so the loop ending does not end it |
| `supervise` | `drain` returns exactly when the last flow ends, from any number of concurrent waiters |
| `generation` | a reload that fails publishes nothing; the message says whether anything is still serving, and only claims so when it is true; a flow keeps the generation it arrived under |
| `daer route explain` | the printed decision is produced by the same compiled generation the data path uses, and its exit status distinguishes "served" from "dropped" |
| `daer-routing::explain` | `decided_by`/`outbound` always equal `first_hit`'s; predicates are grouped as the configuration nests them |
| `daer-dns::wire` | every prefix of a message fails cleanly; compression pointers may only point backwards, with a hop budget |
| `daer-dns::routing` | an undeclared upstream, an unsupported predicate or a missing fallback fails at load, not per query |
| `daer-dns::cache` | a fresh hit advertises the remaining TTL; a stale hit says so; nothing outlives the minimum record TTL; the entry bound holds |
| `daer-dns::resolver` | the cache lock is never held across an `.await`; a self-referential failover is ignored, not followed; the OPT record's TTL word is never rewritten |
| `daer-dns::transport` | a reply with a mismatched id or no response bit is refused; every exchange has a hard timeout; an unimplemented protocol names itself instead of silently answering |
| `daer-dns::server` | a malformed datagram is dropped, never crashes the loop; an oversized UDP answer sets `TC`; `asis` produces silence on both transports |
| `daer-outbound::shadowsocks` | only authenticated ciphers; nonce and salt continue from the handshake into the stream; a truncated record is an error, never a short read |
| `daer-outbound::trojan` | no plaintext constructor; a bare-IP node without `sni` is rejected at parse time; the password never reaches a log line |
| `daer-outbound::property` | a node's security identity is derived structurally and cannot contain a credential |
| `daer-ebpf::epoch` | a failed publish leaves the active slot unchanged; a stamp is verified before the commit; generation 0 is never published |
| `daer-sniff` | no panic on hostile bytes; `NeedMore` is bounded by `MAX_SNIFF_LEN`; a name is reported only when it is actually present |
| `daer-control::sniff` | sniffing never consumes the stream; both a byte budget and a time budget bound it; failing to sniff is an outcome, not an error |
