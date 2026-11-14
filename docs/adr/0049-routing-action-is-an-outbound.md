---
id: ADR-0049
title: "A routing action is an outbound; an election is the dynamic outbound"
status: accepted
date: 2026-11-13
scope: [config/model, config/schema, routing/lowering, control-plane/routing, cli/surface, docs]
supersedes: []
superseded_by: []
amends: [ADR-0001, ADR-0046]
---

# 0049. A routing action is an outbound; an election is the dynamic outbound

- Status: Accepted
- Date: 2026-11-13
- Deciders: daer maintainers
- Related: [ADR-0001](0001-config-format.md), [ADR-0005](0005-kernel-policy-encoding.md),
  [ADR-0046](0046-resource-election-model.md), [ADR-0047](0047-runtime-election-control.md)

## Context

The old rule syntax put the action in the same string as the match:

```toml
rules = ["rule-set(cn) -> direct"]
```

That had three distinct problems:

1. **The action was not a typed object.** It was a function call (`direct`, `proxy(mark: …)`)
   parsed by the same grammar as predicates, so `direct`, `block` and an election name shared
   one untyped slot.
2. **A rule had no stable identity.** Diagnostics referred to an array index; a log line could
   not name the rule an operator wrote.
3. **The model did not say what an election is.** An election is a policy that selects a node;
   its result is an outbound. `direct` and `block` are built-in outbounds. The old shape made
   all three look like strings in the same namespace.

ADR-0046 separated groups from elections but left the rule action as an untyped name. This ADR
finishes that separation.

## Decision

Schema version 3 represents each rule as a table. The action is a typed outbound; the match is
still a boolean expression string, because a tabular boolean encoding is a worse language
(ADR-0001).

### 1. Rule shape

```toml
[routing]
fallback = "direct"

[[routing.rule]]
name = "cn-direct"
match = "rule-set(cn, cn-ip)"
action = "direct"

[[routing.rule]]
name = "ai-proxy"
match = "rule-set(openai, anthropic)"
action = { election = "proxy" }
```

- `name` is required and unique. It is the rule's identity in logs, diagnostics and tests.
- `match` is an expression: predicates joined by `&&`, parameters inside one predicate OR-ed,
  `!` negating. There is no `->` and no action inside it.
- `action` is an `OutboundAction`.
- Array order is priority. There is no `priority` key.

### 2. The outbound vocabulary

```text
Outbound = direct | block | election(name)
Election = a policy that selects one node
Node     = a concrete proxy endpoint
```

TOML spellings:

```text
action   = "direct"                 # built-in local path
action   = "block"                  # built-in drop
action   = { election = "proxy" }  # dynamic selection; result is a node outbound
fallback = "direct"                 # same action type
```

`direct` and `block` are not nodes and are not elections. Election names are referenced only
through the `{ election = "…" }` table, so there is no action-string namespace to shadow.

### 3. Match language is a conjunction normal form

```text
match := predicate ('&&' predicate)*
predicate := '!'? name '(' value (',' value)* ')'
```

- `&&` is AND; commas are OR inside one predicate; `!` negates.
- There is no `||` and no parenthesis. Cross-predicate OR is multiple rules with the same
  action.
- Reason: the datapath encodes one conjunction as one kernel match path. A boolean tree would
  either expand into multiple policies or force a userspace deferral, making kernel/userspace
  parity conditional on syntax.

### 4. One canonical predicate vocabulary

| Predicate | Meaning |
| :--- | :--- |
| `domain(...)` | Domain patterns. |
| `dip(...)` / `sip(...)` | Destination / source IP. |
| `dport(...)` / `sport(...)` | Destination / source port. |
| `l4proto(...)` | TCP / UDP. |
| `pname(...)` | Process name. |
| `mac(...)` / `dscp(...)` | Datapath facts. |
| `ipversion(...)` | IPv4 / IPv6. |
| `rule-set(...)` | Both IP and domain dimensions of a rule set. |
| `ip-set(...)` / `domain-set(...)` | One dimension of a rule set. |

Aliases (`provider`, `ip`, `port`, `rule-set:name`, `provider:name`) are deleted. A rule set is
a named resource, not a keyed parameter.

### 5. Diagnostics carry the action kind

`daer route --why` reports the rule name and the typed action:

```text
rule       : cn-direct (rule-set(cn, cn-ip) -> direct)
action     : direct
```

For an election:

```text
rule       : ai-proxy
action     : election "proxy"
node       : proxy:auto: panel/HK-01
```

A group is never a valid action. If a name matches a group, the error says a group is a
candidate pool and names the election declaration to add.

## Consequences

- Action names no longer collide: builtins are strings, elections are tables.
- Rules have stable names; `daer route --why`, logs and tests can refer to them.
- The match grammar is smaller: it only parses predicates, not actions.
- The kernel policy lowering receives an outbound kind instead of reinterpreting a string.
- This is a clean break: `[routing].rules` is deleted and `schema = 3` is required.
- The rule table is more verbose than one-line strings. That is accepted: a policy file is
  reviewed and changed rarely, and the extra lines buy identity and type separation.

## Enforcement

| Claim | Falsifier |
| :--- | :--- |
| `direct`/`block` are built-in actions | `routing_rules_are_named_tables_with_typed_actions` |
| An election action is a table | `routing_rules_are_named_tables_with_typed_actions` |
| A group cannot be an action | `a_group_is_not_a_routing_action` |
| Rule names are unique | `routing_rule_names_are_unique` |
| `match` has no action | parser test `an_arrow_is_not_part_of_a_match` |
| No alias predicates | builder test `retired_predicate_aliases_are_unknown_functions` |
| `daer route --why` names the rule | `route_explain_names_the_rule_that_fires` |
