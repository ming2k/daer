---
id: ADR-0047
title: "Runtime election control is a delegated admin socket with persistent overrides"
status: accepted
date: 2026-11-12
scope: [cli/surface, control-plane/elections, security/authorization, packaging, observability]
supersedes: []
superseded_by: []
amends: [ADR-0015, ADR-0041, ADR-0046]
---

# 0047. Runtime election control is a delegated admin socket with persistent overrides

- Status: Accepted
- Date: 2026-11-12
- Deciders: daer maintainers
- Related: [ADR-0015](0015-cli-is-four-verbs.md), [ADR-0041](0041-runtime-status-verb.md),
  [ADR-0046](0046-resource-election-model.md)

## Context

ADR-0046 makes an election the routing target. Routing rules no longer change when an
operator wants a different node; the election's current result changes. That needs a runtime
control path that does not require editing `/etc/daer/config.toml` or sending `SIGHUP`, and it
must be available to an operator who is not root.

The existing `/run/daer/control.sock` is deliberately read-only, root-owned and `0600`
(ADR-0041). Mutating it would break that contract and expose every status field to whoever can
write. A second mechanism is required:

- the daemon is the only writer of runtime state;
- the client must not need `CAP_*` or root;
- a change must survive a daemon restart and a reboot;
- a non-root client must not be able to create arbitrary policies or probe arbitrary URLs.

## Decision

### 1. Two sockets, two contracts

| Socket | Mode | Purpose |
| :--- | :--- | :--- |
| `/run/daer/control.sock` | `0600 root:root` | The broad read-only status snapshot (ADR-0041). |
| `/run/daer/admin.sock` | `0600 root:root` (default) | Election views and the `elect`/`reset` commands. Opt-in delegation can make it `0660 root:<group>`. |

The admin socket speaks one JSON request/response per connection and never executes a
client-supplied program or path. A request names an election and a node, or asks for one of the
three read-only views (`nodes`, `groups`, `elections`). The daemon validates the names against
the current generation; unknown names are rejected, not interpreted.

`DAER_ADMIN_GROUP` names an existing group for **opt-in** delegation. When it is absent the
socket stays `0600 root:root`, so runtime election control is root-only by default. When it is
set, the socket becomes `0660` and is chowned to that group; the unit must also carry the group
as a supplementary group (`SupplementaryGroups=`) so the daemon can chown it without adding
`CAP_CHOWN` to the bounding set. There is no world-writable mode. If the group does not exist,
the socket remains root-only and the CLI reports the permission error rather than silently
widening the socket.

### 2. The CLI surface is eight verbs

```text
daer run
daer check
daer route
daer probe
daer status [--nodes | --groups | --elections]
daer elect <ELECTION> <NODE>
daer elect <ELECTION> --reset
daer schema
daer version
```

`status` remains the only read command. `elect` is the only runtime mutation. There is no
`node`, `group`, or `election` top-level command: a resource inventory is a view of the same
snapshot, not a second service, and `status --nodes/--groups/--elections` keeps the surface
flat. `probe` remains the active network diagnostic; `status` reports cached measurements.

### 3. The override is an election, not a configuration rewrite

`daer elect` sets an override in the daemon:

```text
election proxy: runtime override = manual(hk-01)
```

The configured election definition is untouched. `--reset` removes the override and the
election follows its configured rule again. All routes that target the election use the
override for new flows; existing flows keep the node they started on. A node that is not a
candidate of the election is rejected, and a manual election with a node input only accepts
that node.

### 4. Persistence is FHS state, not configuration

The daemon writes `/var/lib/daer/elections.json` atomically, mode `0600`, with a versioned
schema:

```json
{
  "schema": 1,
  "elections": [
    { "election": "proxy", "node": "hk-01" }
  ]
}
```

- Absence of an entry means "follow the configured election"; there is no stored `auto`.
- The file is daemon-owned. A non-root operator reaches it only through the admin socket.
- On startup and after every reload the daemon validates each override by name. An override
  whose election or node disappeared, or whose node is no longer a candidate, is removed with
  a `warn` event.
- Persistence happens before the in-memory change: a command that reports success means the
  state was saved. If the write fails, the command fails and the election is unchanged.
- A corrupt or unknown-schema file is reported and ignored; it never prevents the daemon from
  starting.

### 5. Dynamic policy creation is deliberately absent

`elect` can only set `manual(node)` on an existing election. It cannot create a new election
or a URL-test policy, because a runtime URL would let a non-root admin make the root daemon
request arbitrary internal addresses (SSRF) and would put policy definitions outside the
configuration gate. A future dynamic policy must reference a config-defined probe profile and
must pass the same validation as a static election; that is a separate ADR.

## Consequences

- `[INV-CLI-01]` is amended from seven verbs to eight (`elect` is the new one), and the
  read/write split is explicit: `status` reads, `elect` writes.
- `daer status --nodes/--groups/--elections` is a live query over the admin socket. When the
  daemon is down it fails with a named error; the broad `daer status` keeps its existing
  `state.json` fallback.
- Runtime election control is root-only unless an operator explicitly opts into a group;
  delegation is never a package default.
- The daemon owns two sockets and one persistent state file; opting into non-root control
  requires both a supplementary group and `DAER_ADMIN_GROUP` in a systemd drop-in.
- `daer elect` needs no file capability. With the default root-only socket it needs root;
  with opt-in group delegation it needs only membership. If the binary is ever installed with
  file capabilities, every subcommand would inherit them; the supported deployment is
  systemd `AmbientCapabilities`, not `setcap`.
- A reload preserves valid overrides. A failed reload leaves the running generation and the
  override untouched.

## Negative Knowledge

- **Reusing `control.sock` for writes.** Rejected. ADR-0041's read-only contract is what lets
  an incident responder query status without a write capability.
- **A world-writable admin socket with `SO_PEERCRED` allowlists.** Rejected. The kernel's
  file-permission check is the smallest correct authorization boundary; a world-writable
  socket makes every local user a parser input and turns the daemon's request validation into
  the only gate.
- **A separate `daerctl` binary.** Rejected. The security boundary is the socket, not the
  executable; a second binary adds version skew and a tempting setuid/setcap target.
- **A setuid/setcap `daerctl`.** Rejected. It would run arbitrary CLI parsing with root
  capability. Authorization belongs to the socket's file permissions and `SO_PEERCRED` audit.
- **Writing the state file from the CLI.** Rejected. A non-root writer would bypass the
  socket's authorization; the daemon is the only writer.
- **Persisting the effective node of a latency election.** Rejected. That freezes an adaptive
  choice; only explicit operator overrides are state.
- **Runtime URL-test creation.** Rejected for v1. It is an SSRF surface and a configuration
  gate bypass.
