# ADR-0027 — One intermediate rule set: readers convert to it, one writer encodes it

- Status: superseded by [ADR-0031](0031-drb-v2-and-canonical-rules.md)
- Date: 2026-11-06
- Related: [ADR-0014](0014-drb-rule-binary-and-providers.md), [ADR-0015](0015-cli-is-four-verbs.md), [ADR-0019](0019-rule-asset-topology-and-lookup-mechanics.md), [ADR-0023](0023-constants-have-one-definition.md)
- Supersedes: the `daer-drb convert`-as-a-parallel-path of ADR-0014 §3

---

## Context and Problem Statement

ADR-0014 established DRB as the compiled artifact and `daer-drb` as its producer. It then
specified one verb per source format:

```text
daer-drb compile <input.rules> -o <output.drb>          # text  -> DRB
daer-drb convert <input.dat> --code <code> -o <out.drb> # .dat  -> DRB
```

Each verb converted *to the target*. That is the shape that multiplies: every new source format
is another conversion into the encoder, with its own opinions about the things the encoder
actually cares about. The code made this visible. `convert` carried its own branch per `.dat`
kind, and the two branches disagreed with each other and with the text path:

| Concern | text path (`from_text`) | `.dat` path (`convert`) |
| --- | --- | --- |
| case folding | `to_ascii_lowercase` | **none** — `DomainType::Full` values were pushed verbatim |
| suffix scope | `.x` / `+x` markers parsed | **always** `SelfAndSubdomains`, leading dot kept in the key |
| invalid patterns | accepted silently | accepted silently |
| `@cn` / `@ads` attributes | not representable | **discarded** |
| dedup / sort | `normalize()` per collection | `from_patterns`, a third implementation |
| interval merging | `compile_intervals` | `compile_intervals`, same function, different caller |

Two consequences, both real:

1. **The same rules could compile to different bytes depending on which door they came in.**
   A `.dat` entry with an uppercase character produced an artifact the runtime's own domain
   index would reject as an invalid pattern — a rule that silently never matches.
2. **Attributes were unrecoverable.** The released `geosite.dat` tags 9,039 domains inside the
   categories this project publishes; `google` alone tags 54 of its domains `@ads`. The
   conversion dropped them, so no later stage — not a pipeline, not an operator, not a review —
   could ask "what in this list is an ad domain". The information existed and was thrown away by
   the *shape* of the code, not by a decision.

Meanwhile the reverse direction did not exist at all: a published `.drb` could be inspected as
counts but not turned back into rules. A release was therefore not auditable; the only way to
learn what it routes was to trust the input file.

## Decision

### 1. There is one intermediate representation: `daer-rule-ast::RuleSet`

```text
  geosite.dat  ─┐
  geoip.dat    ─┼─▶  RuleSet  ─▶  daer-routing::DrbSet  ─▶  .drb
  .rules text  ─┤         ▲
  (next format)─┘         │
                    the same type the
                    runtime's text provider
                    lowers through
```

Every reader produces `RuleSet`. Exactly one function, `DrbSet::from_rule_set`, consumes it.
`daer-routing` no longer offers `from_prefixes` or `from_patterns` — the two doors that let a
caller supply pre-classified collections and thereby bypass normalisation. They are deleted, not
deprecated.

### 2. Normalisation lives in the AST, once, and is total

`RuleSet::canonical` folds case, validates patterns, sorts, deduplicates, and merges rules that
differ only in attributes. Interval merging stays in the writer, because it is an encoding
decision (pre-merged ranges are what makes the artifact binary-searchable) and an AST that
merged them would be a second DRB.

The validation is deliberately a second expression of one rule the runtime also enforces: a
pattern the domain index would refuse is a rule that never matches, and a producer that writes
it produces an artifact whose contents differ from its appearance. On the published corpus all
528,840 domain entries pass the runtime's character rule, so this rejects nothing real — it
rejects the mistake.

### 3. Attributes are part of the rule set

`DomainRule` carries the source's attribute names. They are parsed, canonicalised, rendered in
text (`suffix: x @cn @ads`), and filterable (`--without ads`). They are *not* encoded into DRB:
the format stores patterns, and inventing a section for provenance would be a format change
justified by a producer's convenience. The consequence is stated in the type's documentation: a
round trip through an artifact drops attributes, so filtering happens on the AST before encoding.

`--without` removes a rule that carries the attribute, it does not strip the tag. A domain tagged
`@cn @ads` is an ad domain that is also Chinese; keeping it with the tag removed would put ads
into a set whose purpose is to exclude them.

### 4. The producer's verbs follow the pipeline, not the source format

```text
daer-drb read     <src> -o x.rules     # any source -> the intermediate text form
daer-drb compile  x.rules -o x.drb     # the intermediate form -> the only writer
daer-drb decompile x.drb -o x.rules    # the artifact -> the intermediate form
daer-drb inspect  x.drb                # metadata
daer-drb test     x.drb <target>       # does this rule set match
daer-drb convert  <src> -o x.drb       # read+compile, for the one-step case
```

`read` and `compile` are separate verbs because the step between them is where a human looks.
`convert` remains because the published pipeline is a batch conversion and paying two processes
per artifact would be silly — but it is now literally `read` then `compile`, sharing one code
path, so the shortcut cannot drift from the long way.

`decompile` exists so a release is auditable: `decompile` then `compile` must reproduce the
artifact byte for byte, and a test asserts it.

### 5. The runtime shares the AST but not the encoder

`daer-control` accepts `format = "text"` providers and lowers them through
`DrbSet::from_text`, which is now a thin wrapper over `RuleSet::parse`. So the daemon's text
provider and the producer's text reader are the same parser, and cannot disagree about what
`suffix:` means.

This does not weaken ADR-0015. `daer-rule-ast` contains no Protobuf reader and no encoder; the
dependency firewall still forbids `daer-geodata` in `daer-routing` and both `daer-geodata` and
`daer-drb` in `daer-cli`. What the daemon gained is a shared *vocabulary*, which is what stops
the two text readers from being two.

## Consequences

### Positive

- **A new source format is a new reader.** It cannot invent normalisation, because there is
  nowhere to put it that the writer will honour.
- **Two paths, one artifact.** Text and `.dat` naming the same rules compile to identical bytes;
  a test in `crates/daer-routing/tests/ast_boundary.rs` asserts it.
- **Releases are auditable.** `decompile` produces rules a reviewer can read, and recompiling
  them reproduces the artifact.
- **Attributes are preserved and filterable**, which the previous pipeline could not do at all.
- **Invalid rules fail at build time** with a line number, instead of being written into an
  artifact that the runtime silently drops half of.

### Negative and accepted costs

- One more crate in the graph, and a scope-enum bridge (`scope_from_ast` / `scope_to_ast`)
  between `daer-rule-ast` and `daer-routing`. The bridge is two exhaustive matches: adding a
  scope on either side fails to compile until both are updated. That is cheaper than making
  either crate depend on the other's vocabulary.
- `from_prefixes` and `from_patterns` are gone, so out-of-tree callers break. There are none;
  this is a clean break, per policy.
- Text rules grew an `@attribute` suffix syntax that only matters for `.dat` provenance. It is
  inert for hand-written rules and ignored when they have none.

## Enforcement

| Claim | Falsifier |
| --- | --- |
| `daer-rule-ast` is neutral | `the_ast_depends_on_nothing_of_ours` — no `daer-routing`, `daer-geodata`, `daer-config` in its closure |
| The writer cannot read Protobuf | `the_writer_cannot_read_protobuf` — `daer-geodata` absent from `daer-routing`'s closure |
| The daemon links no producer | `the_daemon_links_neither_reader_nor_writer` |
| One AST ⇒ one artifact | `text_and_programmatic_construction_produce_identical_bytes` |
| Artifacts are auditable | `an_artifact_round_trips_through_text` |
| Attributes survive and filter | `attributes_survive_the_ast_and_can_be_filtered_there` |
| The text form is a fixed point | `render_is_a_fixed_point` (unit) and the round-trip test |
