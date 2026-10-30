# ADR-0001 — The configuration format is TOML

- Status: accepted
- Date: 2026-01-07
- Supersedes: the earlier custom-grammar configuration contract

## Context

`daer` started from a port of another project's configuration stack: an ANTLR
grammar reimplemented as a hand-written parser, Go structs mirrored field by field,
defaults recovered from struct tags. That was scaffolding for getting a working
model quickly. It is not a design, and it carries three costs:

1. **The grammar was shaped for text, not for data.** Flat
   `section { key: value }` blocks with keyless scalars, expression values and
   line-oriented rules. Every one of those needs its own parser path and its own
   error reporting, and none of it is expressible to an editor or a schema tool.
2. **The mirrored model carries foreign artifacts.** A field plus a `_set`
   companion because a struct cannot distinguish "absent" from "zero"; a field
   naming a TLS library that does not exist here; `"domain:ttl"` strings joined by
   a colon that is also legal inside domains; health-check knobs declared twice
   with an empty string as their "unset" value.
3. **Two formats is two of everything.** Grammar, decoder, defaults, error
   messages, tests, documentation — permanently.

There is no compatibility debt to protect: this project has no released
configuration and no users of one. Keeping a second syntax would be choosing a
cost that only grows.

## Decision

**The configuration format is TOML. There is no other format, and no importer.**

The model ([`Config`]) is the single source of truth:

| Concern | Where |
| --- | --- |
| Schema, defaults, `Deserialize`/`Serialize` | `daer-config::model` |
| Reading files, `include`, merge rules, rendering | `daer-config::toml_config` |
| Defaults applied and values checked | `daer-config::validate` |
| Rule / filter / policy grammar | `daer-config::expr` |
| Machine-readable contract | `daer-config::schema` (feature `schema`) |

### Why TOML

- It expresses everything the schema *is*: scalars, booleans, integers, strings,
  arrays, nested and inline tables, literal keys (domain names, tags with dots),
  comments, and — importantly — **ordered arrays**, which is how rule order and
  group order survive.
- It has no implicit typing. `no` is a string, `on` is a string, and a bare
  `2024-01-01` is a date rather than three different things depending on the
  parser. For a security-relevant configuration, that is disqualifying for YAML
  and a non-issue for TOML.
- Strictness is enforceable: `deny_unknown_fields` at every level makes a typo an
  error instead of a silently ignored line, and a duplicated scalar after merging
  is an error instead of a silent winner.
- It maps onto `serde` with spans, so the error message can point at the exact
  expression that is wrong.

### What is an expression, and why

Three things are text parsed by `daer-config::expr` rather than TOML data:

| Where | Example |
| --- | --- |
| `routing.rules` | `domain(suffix: a.com) && port(443) -> proxy` |
| `group.filters` | `subtag(sub) && !name(keyword: 'ExpireAt:')` |
| `group.policy`, `dns.*.fallback` | `fixed(0)`, `min-moving-avg` |

A boolean combination of arbitrary predicates has no faithful tabular encoding —
encoding it as nested tables invents a worse expression language with no
precedence, no negation, and no way to say "any of these". The parsed form is also
exactly what the routing engine consumes, so parsing happens once and the AST is
the contract. Everything else in the schema is data.

### Shape decisions worth naming

- kebab-case keys; absence is `Option`, never an empty string sentinel.
- `HealthCheck` is one type, used for `[global.health-check]` defaults and for each
  `[[group.health-check]]` override (`HealthCheckOverride`), instead of five fields
  declared twice.
- `[[node]]` / `[[subscription]]` are tables with `tag`, `url` and `persist`,
  instead of `"tag:url"` strings whose separator also occurs inside URLs.
- `[global.tls] profile = "chrome-current"` names a netune fingerprint preset. An
  unknown preset fails at load time: presenting a different ClientHello than the
  operator asked for is worse than refusing to start (ADR-0002).
- `[dns.fixed-domain-ttl]` is a table of domain → seconds; `[dns.request]` and
  `[dns.response]` lose the meaningless `routing` level.
- `bandwidth-max-*` is typed: `0`, `1048576` (bytes/s), `200 mbps`, `1.5Gbps`.
- No dead knobs. A setting that the daemon does not act on is not in the schema.

### `include`

Globs resolve relative to the file that names them; only files under the entry
file's directory are accepted; cycles are rejected; tables merge key by key;
arrays concatenate; a scalar set by two files is an error, so an override is
always explicit.

## Consequences

- `daer-config` depends on `serde`, `toml` and `glob`. A zero-dependency config
  crate was a property of the port, not of the design.
- Byte-offset diagnostics are exact for a single file and degrade to key paths
  after merging, because a merged value has no spans. `include` is opt-in, and a
  per-file source map would fix it if that ever matters.
- One limitation is inherent to TOML: `subscription` must be either an array of
  strings or an array of tables in a given file, because an array cannot contain
  both shapes. A configuration picks one.
- No aliases or anchors: reusing a health-check block across groups means writing
  it again or moving it into an included file.
- An operator with a configuration in the old syntax must convert it once. There is
  no in-tree converter, deliberately: writing one is writing the decoder again.

## Alternatives rejected

- **Keep the old grammar as a frozen importer.** Permanently two frontends, two
  decoders, two error models, and a second source of truth for defaults — in
  exchange for a one-time convenience for configurations this project never
  shipped.
- **JSON / YAML.** No expressiveness gain over TOML for this shape; YAML's implicit
  typing is a hazard, and JSON forbids comments in a file humans hand-edit.
- **Structured rule objects instead of expression strings.** See above: it is a
  worse expression language.
- **A schema in code only** (builder API, no file). Operators need a file that can
  be reviewed, diffed and deployed by configuration management.
