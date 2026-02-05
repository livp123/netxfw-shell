#!/bin/bash

# 检查是否安装了 bpftool
if ! command -v bpftool &> /dev/null; then
    echo "错误: 未找到 bpftool，请先安装 (apt install linux-tools-common linux-tools-$(uname -r))"
    exit 1
fi

MAP_V4="/sys/fs/bpf/blacklist_v4"
MAP_V6="/sys/fs/bpf/blacklist_v6"

# 自动定位加载器路径
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOADER="$SCRIPT_DIR/../xdp_loader"

if [ ! -f "$LOADER" ]; then
    # 尝试在当前目录查找
    LOADER="./xdp_loader"
fi

usage() {
    echo "用法: $0 [add|del|list|flush|stats|config|load|unload] [参数]"
    echo "示例:"
    echo "  $0 load eth0                 # 加载"
    echo "  $0 add 1.2.3.4               # 拦截单个 IP"
    echo "  $0 del 1.2.3.4               # 移除单个 IP"
    echo "  $0 add 192.168.1.0/24        # 拦截网段"
    echo "  $0 del 192.168.1.0/24        # 移除网段"
    echo "  $0 flush                     # 清空所有黑名单"
    echo "  $0 list                      # 查看列表"
    echo "  $0 monitor                   # 监控拦截日志"
    exit 1
}

if [ "$1" == "load" ]; then
    $LOADER load "$2" "$3" "$4"
    exit 0
elif [ "$1" == "unload" ]; then
    $LOADER unload "$2"
    exit 0
elif [ "$1" == "config" ]; then
    $LOADER config "$2" "$3"
    exit 0
elif [ "$1" == "stats" ]; then
    $LOADER stats
    exit 0
elif [ "$1" == "monitor" ]; then
    $LOADER monitor
    exit 0
fi

if [ "$1" == "flush" ]; then
    echo "正在清空所有黑名单..."
    [ -f "$MAP_V4" ] && bpftool map dump pinned "$MAP_V4" | awk '/key: / {print $2, $3, $4, $5}' | while read -r k; do bpftool map delete pinned "$MAP_V4" key $k; done
    [ -f "/sys/fs/bpf/blacklist_v4_lpm" ] && bpftool map dump pinned "/sys/fs/bpf/blacklist_v4_lpm" | awk '/key: / {print $2, $3, $4, $5, $6, $7, $8, $9}' | while read -r k; do bpftool map delete pinned "/sys/fs/bpf/blacklist_v4_lpm" key $k; done
    [ -f "$MAP_V6" ] && bpftool map dump pinned "$MAP_V6" | awk '/key: / {print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17}' | while read -r k; do bpftool map delete pinned "$MAP_V6" key $k; done
    [ -f "/sys/fs/bpf/blacklist_v6_lpm" ] && bpftool map dump pinned "/sys/fs/bpf/blacklist_v6_lpm" | awk '/key: / {print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21}' | while read -r k; do bpftool map delete pinned "/sys/fs/bpf/blacklist_v6_lpm" key $k; done
    echo "清理完成。"
    exit 0
fi

if [ "$1" == "list" ]; then
    echo "--- IPv4 黑名单 (单个) ---"
    [ -f "$MAP_V4" ] && bpftool map dump pinned "$MAP_V4" | grep -v "found 0 elements"
    echo "--- IPv4 黑名单 (网段) ---"
    [ -f "/sys/fs/bpf/blacklist_v4_lpm" ] && bpftool map dump pinned "/sys/fs/bpf/blacklist_v4_lpm" | grep -v "found 0 elements"
    
    echo "--- IPv6 黑名单 (单个) ---"
    [ -f "$MAP_V6" ] && bpftool map dump pinned "$MAP_V6" | grep -v "found 0 elements"
    echo "--- IPv6 黑名单 (网段) ---"
    [ -f "/sys/fs/bpf/blacklist_v6_lpm" ] && bpftool map dump pinned "/sys/fs/bpf/blacklist_v6_lpm" | grep -v "found 0 elements"
    exit 0
fi

if [ -z "$2" ]; then
    usage
fi

IP=$2
ACTION=$1

# 调用加载器执行添加/删除操作 (加载器已支持 CIDR 解析)
if [ "$ACTION" == "add" ]; then
    $LOADER add "$IP"
elif [ "$ACTION" == "del" ]; then
    $LOADER del "$IP"
else
    usage
fi
exit 0
