# Getting Started with daer

This tutorial walks through building `daer`, generating the eBPF datapath, authoring a minimal configuration, and running the transparent proxy for the first time.

---

## 1. Prerequisites

Before starting, ensure your system has:
- Linux kernel 5.17 or newer (with BTF enabled at `/sys/kernel/btf/vmlinux`).
- Clang and LLVM (`clang`, `llvm-strip`).
- Rust 1.95+ toolchain.
- Root or `CAP_BPF` and `CAP_NET_ADMIN` privileges.

---

## 2. Build the Binaries & Datapath

Clone the repository and compile both the userspace daemon and the eBPF kernel datapath:

```bash
# 1. Compile the Rust workspace
cargo build --release

# 2. Compile the eBPF datapath object (produces target/ebpf/datapath.o)
cargo xtask ebpf
```

Verify that the eBPF object passes the kernel verifier before running:

```bash
cargo xtask kernel-check
```

---

## 3. Create a Minimal Configuration

Create a simple configuration file at `/etc/daer/config.toml` (or locally as `config.toml`):

```toml
schema = 1

[global]
tproxy-port = 12345
wan-interface = ["auto"]
lan-interface = ["eth0"]       # Replace with your client-facing LAN interface
so-mark = 0x0dae               # Required to avoid proxy self-capture

[[node]]
tag = "edge-proxy"
type = "shadowsocks"
server = "example.com"
port = 8388
method = "chacha20-ietf-poly1305"
password = "my-secret-password"

[[group]]
name = "proxy"
policy = "min-moving-avg"

[routing]
rules = [
    "dip(geoip:private) -> direct",
    "domain(geosite:cn) -> direct"
]
fallback = "proxy"
```

Validate your configuration syntax before starting:

```bash
daer config validate -c config.toml
```

---

## 4. Run the Daemon

Start `daer` with root privileges to allow attaching the TC eBPF filter and binding `IP_TRANSPARENT`:

```bash
sudo ./target/release/daer run -c config.toml
```

Look for the startup log confirming the datapath attachment:

```text
INFO interfaces resolved lan=["eth0"] wan=["eth1"]
INFO listening for redirected flows port=12345 ...
INFO datapath attached: redirected flows will be proxied port=12345 device=daer0 peer=daer0peer
```

---

## Next Steps

- For full production setup with `nftables` redirect rules and systemd service auto-start, consult the [Production Deployment Guide](../how-to/deployment.md).
- To inspect routing decisions without running the proxy, read [Diagnose Flows & Rules](../how-to/diagnostics.md).
