# How-To Guides

Task-oriented guides for operators and system administrators. Each guide assumes you have basic familiarity with Linux networking and `daer`.

---

## Available Guides

| Guide | Solves |
| :--- | :--- |
| **[Configure daer](configuration/index.md)** | Build a modular configuration tree: file layout and includes, global settings, subscriptions, nodes and protocols, groups/elections, routing, DNS, rule sets, and TLS. |
| **[Deploy Transparent Proxy](deployment.md)** | End-to-end deployment: Linux 6.6+/TCX requirements, private ingress topology, socket mark loop evasion, and systemd service management. |
| **[Diagnose Flows & Rules](diagnostics.md)** | Troubleshoot routing decisions, inspect unrouted flows, interpret logs, and debug why traffic is direct or proxied without modifying running config. |
| **[Manage Rule Sets and DRB](rule-providers.md)** | Create, compile, and distribute `.drb` rule sets, configure local and remote HTTP rule sets with automated background updates. |
| **[Install DRB Rule Sets Manually](drb-sets-manual-install.md)** | Build the `drb-sets` artifacts, verify them, install them under `/var/lib/daer/rules`, and declare file sources for offline or reproducible operation. |
| **[Run Local Vision Lab](vision-lab.md)** | Stand up a local XTLS-Vision / REALITY test harness using xray to test outbound protocol implementations locally. |

---

For step-by-step beginners' guidance, see [Getting Started](../tutorials/getting-started.md). For complete CLI and configuration options, see [Reference](../reference/index.md).
