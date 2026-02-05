# NetXFW-Shell: 高性能 XDP 动态防火墙

[中文版](README.md) | [English](README_EN.md)

基于 eBPF/XDP 技术实现的轻量级、高性能网络防火墙，支持动态模块化配置、IPv4/IPv6 双栈拦截以及与 Nginx 日志联动的自动化封禁。

## 核心特性

1.  **极速过滤**：在网卡驱动层（XDP）直接拦截黑名单 IP，绕过整个内核网络栈，性能远超 iptables/nftables。
2.  **模块化设计**：
    - **独立模块**：IPv4 和 IPv6 逻辑被拆分为独立的头文件 (`mod_ipv4.h`, `mod_ipv6.h`)，便于维护和扩展。
    - **条件编译**：支持在编译时通过 `ENABLE_IPV6=0` 彻底移除 IPv6 相关代码，减小二进制体积。
    - **功能开关**：支持运行时动态启用/禁用模块。
    - **插件化扩展**：利用 eBPF 尾调用（Tail Calls）技术，支持动态挂载自定义过滤模块。
3.  **动态 Map 容量**：支持在加载程序时通过参数动态调整黑名单 Map 的最大容量（Max Entries）。
4.  **智能内存管理**：使用 `LRU_HASH` Map，自动淘汰旧条目。

## 环境准备

在编译之前，请确保系统中已安装以下依赖：

- **操作系统**: 推荐使用 Linux 内核 5.10+ (支持 XDP 和 BTF)
- **工具链**: `clang`, `llvm`, `make`, `pkg-config`
- **库文件**: `libelf`, `zlib`, `libxdp`, `libbpf`

在 Debian/Ubuntu 上安装：
```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential \
                 libxdp-dev libbpf-dev linux-headers-$(uname -r)
```

## 快速开始

### 1. 编译流程

项目采用模块化设计，支持根据需求自定义编译选项：

```bash
# 场景 A: 默认编译 (包含 IPv4 和 IPv6 支持)
make clean && make

# 场景 B: 仅编译 IPv4 模块 (完全移除 IPv6 代码以获得极致性能)
make clean && make ENABLE_IPV6=0

# 场景 C: 编译插件示例
make plugins
```

### 2. 加载 XDP 程序

加载器 `xdp_loader` 支持动态设置黑名单容量：

```bash
# 使用脚本快捷加载 (默认 10240 容量)
./shell/manage_blacklist.sh load eth0

# 高级加载：指定接口、是否开启 IPv6、黑名单容量 (例如 500,000 条)
# 参数格式: ./xdp_loader <ifname> [ipv6_on|ipv6_off] [max_entries]
./xdp_loader eth0 ipv6_on 500000
```

### 3. 黑名单与网段管理

支持单个 IP 封禁和 CIDR 网段拦截：

```bash
# 封禁单个 IP
./shell/manage_blacklist.sh add 1.2.3.4
./shell/manage_blacklist.sh add 2001:db8::1

# 封禁整个网段 (CIDR 格式)
./shell/manage_blacklist.sh add 192.168.1.0/24
./shell/manage_blacklist.sh add 2606:4700::/32

# 查看当前状态与列表
./shell/manage_blacklist.sh list

# 实时监控拦截日志 (新功能)
./shell/manage_blacklist.sh monitor

# 移除特定规则
./shell/manage_blacklist.sh del 1.2.3.4
./shell/manage_blacklist.sh del 192.168.1.0/24

# 一键清空所有规则
./shell/manage_blacklist.sh flush
```

### 4. 插件化管理 (动态扩展)

利用尾调用 (Tail Call) 机制，无需重新加载主程序即可动态增加过滤逻辑：

```bash
# 加载端口过滤插件 (拦截 8080 端口)
# 参数格式: ./xdp_loader plugin <plugin_path> <slot_index>
./xdp_loader plugin mods/plugin_port_block.bpf.o 0

# 卸载插件 (清空指定槽位)
./xdp_loader plugin_del 0
```

### 5. 开启 Nginx 联动自动化防御

```bash
# 启动脚本，监控 Nginx 404 攻击并自动封禁
nohup ./shell/nginx_to_xdp.sh &
```

### 6. 实时监控 (新)
项目现在支持通过 BPF Ring Buffer 实时查看被拦截的流量：
```bash
# 启动实时监控
sudo ./shell/manage_blacklist.sh monitor <interface>
```
该功能会显示：
- 源/目的 IP
- 源/目的 端口
- 协议类型 (TCP/UDP/ICMP)

### 7. 性能优化说明
- **CI/CD 自动打包**: 通过 GitHub Actions 自动构建并发布两个版本的二进制压缩包（全栈版与仅 IPv4 版），极大简化了分发流程。
- **智能挂载模式**: 自动尝试三种挂载模式（Offload -> Native -> Generic），失败时自动降级，确保在各种硬件和驱动环境下都能成功运行。
- **Fast Path**: 程序在主入口处预先判断 IPv4/IPv6 模块是否启用，避免了在禁用模块时的无效 Map 查找。
- **Per-CPU Stats**: 使用 Per-CPU Array 进行无锁统计，适合高并发场景。
- **Ring Buffer**: 使用 Linux 5.8+ 引入的 Ring Buffer 替代传统的 Perf Event Array，性能更高且内存占用更均衡。

## 项目结构

- `xdp_blacklist.bpf.c`: 内核态 XDP 程序主入口。
- `mod_ipv4.h`: IPv4 过滤逻辑模块。
- `mod_ipv6.h`: IPv6 过滤逻辑模块。
- `xdp_loader.c`: 用户态加载器，支持动态 Map 属性修改。
- `manage_blacklist.sh`: 综合管理脚本，封装了复杂的命令行操作。
- `nginx_to_xdp.sh`: Nginx 日志分析与自动封禁脚本。
- `common.h`: 内核与用户态共享的枚举和结构体定义。

## 卸载

```bash
./shell/manage_blacklist.sh unload eth0
```

## 二进制下载
项目通过 GitHub Actions 自动构建并发布，您可以在 [Releases](../../releases) 页面下载以下预编译包：
- **netxfw-fullstack.zip**: 包含 IPv4 和 IPv6 支持。
- **netxfw-ipv4-only.zip**: 仅包含 IPv4 支持（极致性能）。

每个压缩包内包含：`xdp_loader` (加载器)、`xdp_blacklist.bpf.o` (内核程序) 以及 `shell/` (管理脚本)。
