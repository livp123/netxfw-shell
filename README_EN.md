# NetXFW-Shell: High-Performance XDP Dynamic Firewall

[中文版](README.md) | [English](README_EN.md)

A lightweight, high-performance network firewall based on eBPF/XDP technology. Supports dynamic modular configuration, IPv4/IPv6 dual-stack blocking, and automated defense integrated with Nginx logs.

## Core Features

1.  **Extreme Filtering**: Blocks blacklisted IPs directly at the Network Interface Card (NIC) driver layer (XDP), bypassing the entire kernel network stack. Performance far exceeds iptables/nftables.
2.  **Modular Design**:
    - **Independent Modules**: IPv4 and IPv6 logic are separated into independent headers (`mod_ipv4.h`, `mod_ipv6.h`) for easy maintenance.
    - **Conditional Compilation**: Supports completely removing IPv6 code via `ENABLE_IPV6=0` at compile time to reduce binary size.
    - **Feature Toggles**: Supports enabling/disabling modules dynamically at runtime.
    - **Plugin Extension**: Utilizes eBPF Tail Calls to support dynamic mounting of custom filtering modules.
3.  **Dynamic Map Capacity**: Supports adjusting the maximum capacity (Max Entries) of the blacklist Map dynamically during program loading.
4.  **Smart Memory Management**: Uses `LRU_HASH` Map to automatically evict old entries.

## Prerequisites

Before compiling, ensure the following dependencies are installed:

- **OS**: Linux Kernel 5.10+ recommended (BTF and XDP support required).
- **Toolchain**: `clang`, `llvm`, `make`, `pkg-config`.
- **Libraries**: `libelf`, `zlib`, `libxdp`, `libbpf`.

On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential \
                 libxdp-dev libbpf-dev linux-headers-$(uname -r)
```

## Quick Start

### 1. Compilation

The project uses a modular design with customizable build options:

```bash
# Scenario A: Default build (includes IPv4 and IPv6 support)
make clean && make

# Scenario B: IPv4 only (completely removes IPv6 for maximum performance)
make clean && make ENABLE_IPV6=0

# Scenario C: Build plugin examples
make plugins
```

### 2. Loading the XDP Program

The loader `xdp_loader` supports dynamic configuration of blacklist capacity:

```bash
# Quick load using script (default 10240 entries)
./shell/manage_blacklist.sh load eth0

# Advanced load: specify interface, IPv6 toggle, and capacity (e.g., 500,000 entries)
# Format: ./xdp_loader <ifname> [ipv6_on|ipv6_off] [max_entries]
./xdp_loader eth0 ipv6_on 500000
```

### 3. Blacklist & Subnet Management

Supports single IP blocking and CIDR subnet interception:

```bash
# Block a single IP
./shell/manage_blacklist.sh add 1.2.3.4
./shell/manage_blacklist.sh add 2001:db8::1

# Block an entire subnet (CIDR format)
./shell/manage_blacklist.sh add 192.168.1.0/24
./shell/manage_blacklist.sh add 2606:4700::/32

# List current status and rules
./shell/manage_blacklist.sh list

# Real-time monitoring of blocked logs
./shell/manage_blacklist.sh monitor

# Show traffic statistics
./shell/manage_blacklist.sh stats

# Remove a specific rule
./shell/manage_blacklist.sh del 1.2.3.4
./shell/manage_blacklist.sh del 192.168.1.0/24

# Flush all rules
./shell/manage_blacklist.sh flush
```

### 4. Plugin Management (Dynamic Extension)

Utilize Tail Call mechanism to add filtering logic without reloading the main program:

```bash
# Load port block plugin (blocks port 8080)
# Format: ./xdp_loader plugin <plugin_path> <slot_index>
./xdp_loader plugin mods/plugin_port_block.bpf.o 0

# Unload plugin (clear specific slot)
./xdp_loader plugin_del 0
```

### 5. Automated Defense with Nginx

```bash
# Start script to monitor Nginx 404 attacks and auto-block IPs
nohup ./shell/nginx_to_xdp.sh &
```

### 6. Real-time Monitoring

Monitor intercepted traffic in real-time via BPF Ring Buffer:
```bash
# Start real-time monitoring
sudo ./shell/manage_blacklist.sh monitor <interface>
```
Displays:
- Source/Destination IP
- Source/Destination Port
- Protocol (TCP/UDP/ICMP)

### 7. Performance & Optimizations
- **CI/CD Auto-Packaging**: Automatically builds and releases two binary versions (Fullstack and IPv4-only) via GitHub Actions.
- **Smart Attachment**: Automatically tries three XDP modes (Offload -> Native -> Generic), falling back if a mode is unsupported.
- **Fast Path**: Pre-checks module status in the main entry to avoid redundant Map lookups when modules are disabled.
- **Per-CPU Stats**: Lockless counters using Per-CPU Array for high-concurrency scenarios.
- **Ring Buffer**: Uses Linux 5.8+ Ring Buffer instead of Perf Event Array for better performance and memory efficiency.

## Project Structure

- `xdp_blacklist.bpf.c`: Main kernel-side XDP entry.
- `mod_ipv4.h`: IPv4 filtering logic.
- `mod_ipv6.h`: IPv6 filtering logic.
- `xdp_loader.c`: User-space loader with dynamic Map adjustment.
- `manage_blacklist.sh`: Wrapper script for CLI operations.
- `nginx_to_xdp.sh`: Nginx log analysis and auto-blocking script.
- `common.h`: Shared definitions between kernel and user space.

## Unload

```bash
./shell/manage_blacklist.sh unload eth0
```

## Binary Downloads
Pre-compiled binaries are available on the [Releases](../../releases) page:
- **netxfw-fullstack.zip**: Includes IPv4 and IPv6 support.
- **netxfw-ipv4-only.zip**: IPv4 only (maximum performance).

Each package contains: `xdp_loader`, `xdp_blacklist.bpf.o`, and the `shell/` directory.
