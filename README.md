<div align="center">

# daer

**A high-performance transparent network proxy and traffic router for Linux.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](./LICENSE)
[![Rust: 1.95+](https://img.shields.io/badge/Rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![Linux: >= 6.6](https://img.shields.io/badge/Linux-Kernel_%3E%3D_6.6-green.svg)](https://www.kernel.org)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)]()

[English](README.md) &bull; [简体中文](README.zh-CN.md)

[About](#about-the-project) &bull; [Mission](#our-mission) &bull; [Capabilities](#capabilities) &bull; [Characteristics](#key-characteristics) &bull; [Quick Start](#quick-start) &bull; [Documentation](docs/) &bull; [Disclaimer](#disclaimer)

</div>

---

## About the Project

daer is a transparent network proxy and traffic routing daemon designed for modern Linux environments. Operating at the operating system network tier, daer automatically classifies, routes, and relays network traffic without requiring manual proxy settings on individual client applications or devices.

By eliminating per-application proxy configurations, browser extensions, and routing friction, daer provides an invisible, high-throughput gateway that streamlines network traffic management across local and upstream networks.

---

## Our Mission

The mission of daer is to explore and deliver high-performance, deterministic network traffic routing for modern Linux environments.

We believe that system-level network tools should be lightweight, reliable, and invisible to daily workflows. By leveraging modern Rust and kernel-level network primitives, daer aims to provide developers, network engineers, and system administrators with a pure, memory-safe, and robust foundation for traffic management, protocol research, and network optimization.

---

## Capabilities

- **System-Wide Transparent Interception**: Intercepts and dispatches network traffic at the system level. Client applications, background services, and local devices benefit from unified proxying without per-app configuration.
- **Intelligent Flow Routing**: Distinguishes direct local traffic from upstream proxy routes in real time based on high-performance IP and domain rule sets.
- **Modern Protocol Relaying**: Interoperates seamlessly with modern, standard encrypted network protocols and outbounds for resilient data transfer.
- **Encrypted DNS Pipeline**: Resolves hostnames through configurable encrypted DNS transports (DoH, DoT, TCP, UDP), providing consistent and tamper-resistant DNS resolution.
- **Gateway & Router Deployment**: Ready for deployment on Linux-based routers or edge gateways, providing transparent network management for all clients on the local network.

---

## Key Characteristics

- **Zero-Intrusion Ergonomics**: Operates quietly in the background without needing PAC files, client-side extensions, or manual SOCKS5/HTTP toggling.
- **Extreme Efficiency & Low Footprint**: Built with modern Rust for memory safety, high concurrency, and near line-rate throughput with minimal CPU and memory overhead.
- **Protocol Robustness**: Engineered to handle complex network topologies, high latency variance, and challenging packet conditions gracefully.
- **Built-in First-Party Diagnostics**: Configuration checking, route simulation (`daer route`), active node probes (`daer probe`), a read-only runtime inspector (`daer status --nodes/--groups/--elections`), and runtime election control (`daer elect`) with persisted overrides.

---

## Quick Start

### Prerequisites

- Linux operating system (kernel 6.6 or newer; TCX is required)
- Root privileges or the `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON` and `CAP_SYS_ADMIN`
  capabilities (`CAP_SYS_ADMIN` creates the private `daer0ns` ingress namespace, the local
  transparent-capture entry side)
- Rust toolchain (1.95+) and Clang / LLVM

### Build & Run

```bash
# Clone the repository
git clone https://github.com/ming2k/daer.git
cd daer

# Build the userspace binary and kernel datapath
cargo build --release
cargo xtask ebpf

# Validate your configuration
daer check -c /etc/daer/config.toml --nodes

# Launch the daemon
sudo daer run -c /etc/daer/config.toml
```

For configuration syntax and deployment recipes, consult the [Documentation](docs/).

---

## Documentation

Detailed guides and specifications are organized within the `docs/` directory:

- [Getting Started Tutorial](docs/tutorials/getting-started.md) &mdash; End-to-end setup and first run.
- [Configuration Reference](docs/reference/configuration.md) &mdash; Complete TOML configuration options and syntax.
- [CLI Reference](docs/reference/cli.md) &mdash; Detailed command-line flags, subcommands, and usage.
- [Network Diagnostics](docs/how-to/diagnostics.md) &mdash; Verifying routing decisions and node health.
- [Production Deployment](docs/how-to/deployment.md) &mdash; Systemd service units and firewall integration.
- [Architecture Overview](docs/explanation/architecture-overview.md) &mdash; System architecture and operational mechanics.

---

## Disclaimer

### 1. Educational & Research Purpose

This software is an open-source research and engineering project focused on computer networking, transparent traffic redirection, and transport protocol performance. It is developed solely for legitimate technical experimentation, academic research, and lawful network administration.

### 2. Legal Compliance & Operator Responsibility

Users are solely responsible for ensuring that their deployment and use of this software strictly comply with all applicable local, national, and international laws, regulations, and administrative requirements. This tool must not be used for any activity that infringes on third-party rights, disrupts public network infrastructure, or violates telecommunication regulations.

### 3. Technical Neutrality & Zero Hosted Services

The authors and maintainers provide this software purely as source code. The project does not operate, host, or provide any proxy servers, VPN nodes, routing infrastructure, or subscription services. The software collects no telemetry and stores no personal information.

### 4. Limitation of Liability

This software is provided "AS IS" and without warranty of any kind, express or implied. Under no circumstances shall the authors, copyright holders, or contributors be liable for any direct, indirect, incidental, or consequential damages or legal consequences arising from the use or misuse of this software.

---

## License

Licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](./LICENSE).
