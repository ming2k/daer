---
id: ADR-0039
title: "Remove rule attributes from Canonical Rule Source"
status: accepted
date: 2026-11-11
scope: [routing/drb, rule-ast, daer-drb, drb-sets, docs]
supersedes: []
superseded_by: []
---

# 0039. Remove rule attributes from Canonical Rule Source

- Status: Accepted
- Date: 2026-11-11
- Deciders: daer maintainers
- Related: [ADR-0027](0027-one-intermediate-rule-set.md), [ADR-0031](0031-drb-v2-and-canonical-rules.md), [ADR-0036](0036-canonical-rule-source-v2-and-symbolic-syntax.md)

## Context

ADR-0027 introduced `@attribute` suffixes on domain rules (`x.com @cn @ads`) so that
attributes carried by a legacy `.dat` file could be filtered while the rules were still
text: `daer-drb compile --without ads`. The attributes were never encoded into DRB; they
existed only in the intermediate text and in `DomainRule`.

The current project does not use that provenance layer:

- `drb-sets` publishes whole upstream categories. It does not filter attributes during
  release builds, and the generated rules carry no attributes for most categories.
- Across the current corpus, 728 of 338,799 domain lines carry an attribute (0.2%).
- Keeping attributes requires a second grammar (`rsplit` on whitespace, `@` handling,
  attribute validation and merging) and an extra `--without` flag on the producer.
- The same filtering can be done before generation, or by choosing a different upstream
  category, without teaching every reader a provenance suffix it cannot store.

## Decision

Remove `@attribute` from Canonical Rule Source and from the producer tooling:

1. `daer_rule_ast::DomainRule` no longer has an `attributes` field.
2. `RuleSet` no longer exposes `drop_attribute` or `strip_attributes`.
3. The CRS parser rejects a rule containing `@` instead of silently treating it as a
   domain or an IP.
4. `daer-drb compile` no longer accepts `--without`.
5. `dat_to_rules.py` ignores the upstream `.dat` attribute fields and emits patterns only.
6. `drb-sets` no longer exposes a `without` key in `config/rules.toml` or passes the flag
   to the compiler.
7. The DRB v2 binary format is unchanged; this is a text-grammar and producer-surface
   change only.

`daer-drb` remains a one-file compiler: it reads one `.rules` input and writes one `.drb`.
It does not merge rule files, apply overlays, or filter provenance. Those are the
`drb-sets` pipeline's responsibilities (`merge_rules.py` and `build.sh`).

## Negative Knowledge and Discarded Alternatives

- **Keep attributes but make them optional.** Rejected: the parser and merge code still
  carry a second grammar for a feature the pipeline does not use.
- **Strip attributes at generation but keep the parser.** Rejected: a half-measure that
  still accepts a suffix it cannot store, and still needs the `--without` surface.
- **Move attributes to a sidecar metadata file.** Rejected: a second source of truth for
  the same rule, with no consumer in the current project.
- **Use attributes for filtering before generation.** Accepted as the migration path:
  filter the upstream data or choose a different category before writing `.rules`.

## Consequences

- A `.rules` file containing `@...` is now a parse error with a message naming the
  unsupported metadata. The migration is to remove the suffix or filter the source first.
- `DomainRule` is simpler, and CRS has one rule per line with no whitespace suffix.
- The DRB round-trip invariant is unchanged: `compile(decompile(drb)) == drb`.
- `daer-drb --without` disappears from the CLI; scripts that used it must filter their
  source text instead.
- The `drb-sets` release pipeline no longer exposes attribute filtering. The existing
  generated rules are regenerated without attributes.
