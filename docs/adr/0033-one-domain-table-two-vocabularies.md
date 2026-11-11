# ADR-0033 — One domain table, two vocabularies, no engines

- Status: accepted
- Date: 2026-11-06
- Related: [ADR-0012](0012-optional-fake-ip-ebpf.md), [ADR-0023](0023-constants-have-one-definition.md), [ADR-0031](0031-drb-v2-and-canonical-rules.md), [ADR-0032](0032-flat-front-coded-domain-table.md)
- Supersedes: the `DomainIndex` / `DomainKey` split of ADR-0014 §1
- Amends: [ADR-0032](0032-flat-front-coded-domain-table.md) — removes the `to_domain_index` bridge it recorded as accepted debt.

---

## Context

ADR-0032 replaced the trie with a flat front-coded table, but recorded one piece of debt:

> `to_domain_index` still materialises a `DomainIndex` for the evaluator's `MatchValue`. That is
> a deliberate, documented per-generation bridge, not the data path; replacing it means changing
> `MatchValue`, which this ADR does not attempt.

That bridge was the last place the retired design survived, and it had three costs:

1. **Two domain structures in one process.** The artifact decoded to a flat table, then every
   generation rebuilt a `DomainIndex` from it — 38 ms for `geosite:cn`, allocating a `HashSet`,
   a `HashMap`, and ~110,000 `Box<str>`. The table existed only to be thrown away.
2. **`DomainKey` forced the wrong shape on every caller.** `DomainIndex::new(key, values, …)`
   split a rule into a key and a value, so a caller holding a mixed spelling had to
   group values by key and construct one index per key — and then ask each of them. Four engines,
   four call sites.
3. **The engines were dead weight on the routing path.** `aho-corasick` and `regex` were linked
   into `daer-routing` for a corpus in which the measured distribution over every published set
   was 99.99% suffix, **zero** keyword, and eight regexes.

## Decision

### 1. There is one domain structure: `DomainTable`

`DomainIndex` and `DomainKey` are deleted. `DomainTable` (ADR-0032) is the only domain structure;
`DrbSet` holds one, `MatchValue::Domain` holds one, and a config's inline `domain(...)` compiles
into one. `DrbSet::domains()` returns `&DomainTable`, so nothing rebuilds anything.

### 2. Routing accepts two pattern kinds, spelled the same everywhere

> **Amended by [ADR-0036](0036-canonical-rule-source-v2-and-symbolic-syntax.md):** the
> `full:`/`suffix:` spellings below were replaced by the symbolic forms `=name`, `name` and
> `.name`. The structural decision — two kinds, one table, one vocabulary everywhere — stands.

| written | matches |
| --- | --- |
| `=name` | exactly `name` |
| `name` | `name` and every subdomain |
| `.name` | subdomains only |

A bare name is a suffix **in a config rule and in a `.rules` file alike**. Previously
`domain(example.com)` was an error demanding a keyed spelling, while the same text
in a rule file meant a suffix — one spelling, two meanings. There is now one vocabulary.

`keyword:` and `regex:` are refused *by name* with a message saying to expand them upstream.

### 3. `daer-dns` owns its own exclusion language

`dns.fake-ip.exclude` keeps `keyword:` and `regex:`, implemented in
`daer-dns/src/exclusions.rs`, because it is a different problem:

| | routing | fake-ip exclusion |
| --- | --- | --- |
| source | published corpus, thousands of entries | a handful of hand-written lines |
| frequency | per connection, on the matching path | once per DNS query |
| size matters | yes — every client downloads it | no |
| needs substring/regex | no (measured: zero) | yes — "anything ending in `.internal`" |

Sharing one structure forced the routing path to carry an automaton and a regex engine for a
syntax nobody wrote. Splitting costs ~150 lines in `daer-dns` and lets each side be right.

This is the ADR-0023 rule applied to a type instead of a constant: **a thing that two subsystems
need for different reasons should have one definition and one owner, and that owner is the
subsystem with the requirement**, not the shared library that happened to have it first.

## Consequences

### Positive

- **One structure, one pass.** No per-generation rebuild; the 38 ms `to_domain_index` cost and
  the ~6.9 MB `DomainIndex` it allocated are gone.
- **Two crates stop linking two engines.** `aho-corasick` leaves `daer-routing`; `regex` stays
  only where it is used.
- **One meaning per spelling**, in config and rules alike.
- **`SuffixScope` has one definition**, in `daer-rule-ast`, as ADR-0023 requires.
- Verified unchanged end to end: all 24 published artifacts still round-trip
  `compile(decompile(drb))` to identical bytes, and every size improvement from ADR-0032 holds.

### Negative and accepted costs

- `keyword:`/`regex:` in a **routing** rule is now a warning, not a match. A configuration using
  them loses those predicates. This is the clean break: the message names the fix.
- `daer-dns` and `daer-routing` each parse a `kind:value` spelling. They accept overlapping but
  not identical grammars, deliberately. A single shared parser would be the same mistake in the
  other direction.
- `DomainTable::patterns()` reports canonical spellings derived from the table, not the literal
  text an operator typed. Diagnostics show what will be matched.

## Enforcement

| Claim | Falsifier |
| --- | --- |
| A bare name is a suffix, in both vocabularies | `a_bare_domain_is_a_suffix` |
| A removed key is refused by name with a fix | `a_removed_domain_key_names_its_replacement`, `keyword_and_regex_are_refused_by_name` |
| Fake-IP keeps keyword/regex | `daer_dns::exclusions` tests |
| Coverage pruning and scopes survive | `daer_routing::domain` tests |
| No `DomainIndex` can return | it does not exist; `daer-routing` no longer links `aho-corasick` |
| Artifacts unaffected | `drb-sets` CI: 24/24 byte-identical round trip |
