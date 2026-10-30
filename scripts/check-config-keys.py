#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fails when a configuration key is accepted but never consumed (ADR-0006).

# Why this is a script and not a test

It has to look at the *whole* workspace, including crates that do not depend on each other, and
it has to distinguish "declared in the model" from "read by the daemon". A unit test inside
`daer-config` cannot see the daemon; a test inside `daer-control` cannot see the DNS resolver.
A grep over the tree can see both.

# What counts as consumed

A field is consumed when its name appears as a member access (`.field`) somewhere outside
`daer-config`'s own `model.rs`/`schema.rs`/`validate.rs`. The last two are excluded because
*validating* a key is not honouring it: `global.mptcp` was range-checked and never used, and that
is exactly the state this script exists to catch.

# The three legitimate answers

ADR-0006 allows a key exactly one of:

1. **implemented** — some code reads it;
2. **removed** — it is not in the model, so `deny_unknown_fields` rejects it by name;
3. **documented as a gap** — impossible here: the allowlist below is empty on purpose, and adding
   an entry is a decision that has to be argued in review, not a convenience.

Exit code is 1 when any key is unconsumed, so `make ci` fails.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Structs whose fields are configuration keys. Every nested table is listed so a new table
# cannot be added without being audited.
CONFIG_STRUCTS = [
    "Global",
    "Tls",
    "HealthCheck",
    "HealthCheckOverride",
    "Dns",
    "DnsRouting",
    "Routing",
    "Group",
    "Filter",
    "Node",
    "Subscription",
    "Config",
]

# Fields that are plumbing rather than behaviour, and why.
SKIP = {
    # The schema gate: enforced by `daer-config`'s validator by construction.
    "schema",
    # A loader directive, consumed inside `daer-config::toml_config` while assembling the tree.
    "include",
}

# Keys a caller may read *through a method* instead of as a field. The script greps for the
# method name as well, so this list only needs entries where the method name differs from the
# field name in a way the heuristic cannot see.
METHOD_ALIASES = {
    "bootstrap_resolver": ["bootstrap_resolvers"],
}


def fields_of(struct_name: str, source: str) -> list[str]:
    match = re.search(
        rf"pub struct {struct_name} \{{(.*?)\n\}}", source, re.S
    )
    if not match:
        return []
    body = match.group(1)
    return re.findall(r"\n    pub (\w+):", body)


def consumed(field: str) -> bool:
    names = [field] + METHOD_ALIASES.get(field, [])
    patterns = [f".{name}" for name in names]
    for path in (ROOT / "crates").rglob("*.rs"):
        if path.parts[-3] == "daer-config" and path.name in {
            "model.rs",
            "schema.rs",
            "validate.rs",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(pattern in text for pattern in patterns):
            return True
    return False


def main() -> int:
    source = (ROOT / "crates/daer-config/src/model.rs").read_text(encoding="utf-8")
    dead: list[tuple[str, str]] = []
    total = 0
    for struct_name in CONFIG_STRUCTS:
        fields = fields_of(struct_name, source)
        if not fields:
            print(f"error: no fields found for {struct_name}; the parser drifted from the model")
            return 1
        for field in fields:
            if field in SKIP:
                continue
            total += 1
            if not consumed(field):
                dead.append((struct_name, field))

    if dead:
        print(f"{len(dead)} of {total} configuration keys are accepted and never consumed:")
        for struct_name, field in dead:
            print(f"  {struct_name}.{field}")
        print()
        print("ADR-0006: a key the schema accepts must either take effect or not exist.")
        print("Implement it, or remove it from `model.rs` so `deny_unknown_fields` rejects it.")
        return 1

    print(f"config: every one of {total} keys outside `daer-config` has a consumer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
