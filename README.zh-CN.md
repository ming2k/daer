<div align="center">

# daer

**面向高吞吐、低延迟与自动化调度的 Linux 高性能透明网络代理系统。**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](./LICENSE)
[![Rust: 1.95+](https://img.shields.io/badge/Rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![Linux: >= 6.6](https://img.shields.io/badge/Linux-Kernel_%3E%3D_6.6-green.svg)](https://www.kernel.org)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)]()

[English](README.md) &bull; [简体中文](README.zh-CN.md)

[关于项目](#关于项目) &bull; [使命宗旨](#使命宗旨) &bull; [核心能力](#核心能力) &bull; [主要特点](#主要特点) &bull; [快速上手](#快速上手) &bull; [官方文档](docs/) &bull; [免责声明](#免责声明)

</div>

---

## 关于项目

daer 是一款运行于现代 Linux 环境下的高性能透明网络代理与流量调度系统。它在操作系统网络层对流量进行集中调度与转发，无需在各个终端应用程序或浏览器中逐一配置代理参数。

通过消除单应用配置、插件依赖与繁琐的网络规则，daer 提供了一个静默且高效的流量中继通道，无缝协同本地系统与上游网络。

---

## 使命宗旨

daer 的使命是探索并实现现代化 Linux 系统中可预测、确定性且高吞吐的网络流量调度机制。

我们追求轻量、可靠且对日常工作完全透明的系统级工具。依托现代 Rust 与内核级网络原语，daer 致力于为系统管理员、网络工程师以及开源开发者提供一个内存安全、结构严谨且易于运维的网络工程底座。

---

## 核心能力

- **系统级无感透明接管**：在操作系统网络层对指定流量进行自动化接管与转发，客户端应用无需单独配置代理端口即可正常联网。
- **高精度智能流分流**：依托高性能规则集，毫秒级区分局域网直连流量与外部代理中继流量，避免不必要的路由开销与网络跳点。
- **主流标准协议兼容**：原生支持多种主流的加密网络代理协议与出站类型，保障数据传输的健壮与稳定。
- **安全多协议 DNS 解析**：支持 DoH、DoT、TCP、UDP 等多种加密与标准 DNS 传输协议，提供高一致性、防篡改的域名解析服务。
- **网关与路由器级部署**：支持部署于软路由或边缘网关设备，一次配置，即可为局域网内的各类终端设备提供统一的透明网络接力。

---

## 主要特点

- **零侵入与极简体验**：纯后台静默运行，无需维护复杂的客户端规则，无需手动切换 SOCKS5/HTTP 端口，保障工作流平滑顺畅。
- **极度高效与超低资源占用**：采用纯 Rust 语言构建，兼具高并发吞吐能力与严格的内存安全保证，在极低的 CPU 和内存开销下维持线速中继。
- **链路健壮与环境适应**：针对复杂网络拓扑与丢包波动环境进行了协议层优化，具备出色的传输容错与恢复能力。
- **完善的第一方诊断工具**：内置第一方配置验证工具、实时路由规则仿真（`daer route`）、节点全链路探测（`daer probe`）、只读运行时快照（`daer status --nodes/--groups/--elections`）与运行时选举控制（`daer elect`，覆盖项持久化），运维排障清晰明了。

---

## 快速上手

### 系统要求

- Linux 操作系统（内核版本 6.6 或更高，必须支持 TCX）
- Root 权限，或 `CAP_NET_ADMIN`、`CAP_BPF`、`CAP_PERFMON`、`CAP_SYS_ADMIN` 能力（`CAP_SYS_ADMIN` 用于创建私有 `daer0ns` 入口命名空间，即 ingress 透明接管入口侧）
- Rust 工具链（1.95+）及 Clang / LLVM

### 构建与启动

```bash
# 克隆仓库
git clone https://github.com/ming2k/daer.git
cd daer

# 编译用户态程序与内核数据面
cargo build --release
cargo xtask ebpf

# 验证配置文件正确性与节点可用性
daer check -c /etc/daer/config.toml --nodes

# 启动守护进程
sudo daer run -c /etc/daer/config.toml
```

详细的配置语法规范与部署指引请参阅 [官方文档](docs/)。

---

## 官方文档

项目深入指引与技术手册遵循 Diátaxis 架构规范组织于 `docs/` 目录：

- [新手入门教程](docs/tutorials/getting-started.md) &mdash; 从零开始的安装、配置与首次运行实战。
- [配置参考手册](docs/reference/configuration.md) &mdash; 完整的 TOML 配置项规范与参数说明。
- [CLI 命令参考手册](docs/reference/cli.md) &mdash; 完整的命令行子命令及参数说明。
- [网络诊断与排错指南](docs/how-to/diagnostics.md) &mdash; 路由判定仿真、节点健康检测与故障定位。
- [生产环境部署实践](docs/how-to/deployment.md) &mdash; Systemd 单元配置、防火墙交互与性能调优。
- [系统架构概览](docs/explanation/architecture-overview.md) &mdash; 系统运作机制与设计哲学。

---

## 免责声明

### 1. 学术研究与技术验证

本软件属于专注于计算机网络体系结构、透明网络中继与传输协议性能优化的开源研究项目。软件的开发与发布旨在进行合法合规的技术实验、网络性能调优及学术探讨。

### 2. 合规使用与操作者责任

使用者在安装、部署及使用本软件的过程中，应严格遵守其物理所在国家和地区的相关法律法规及网络监管政策。本软件严禁用于任何侵犯第三方合法权益、危害网络基础设施安全或违反属地法律法规的活动。

### 3. 技术中立与零托管服务

本项目作为开源技术成果发布，开发者团队不持有、不运营亦不提供任何代理服务器、VPN 节点或商业网络中继服务。本软件不包含任何遥测跟踪代码，不收集亦不存储任何用户个人身份信息与网络流量数据。

### 4. 责任限制与担保豁免

本软件严格按照“现状”（AS-IS）提供，不包含任何明示或暗示的担保。对于因使用或无法使用本软件所产生的任何直接、间接损失、合规风险或法律后果，软件作者及贡献者概不承担连带责任。

---

## 许可证

本项目依据 [GNU Affero 通用公共许可证第三版 (AGPL-3.0)](./LICENSE) 开源。
