#!/bin/bash

# Nginx 日志路径
LOG_FILE="/var/log/nginx/access.log"
# 阈值：10秒内出现 5 次 404 则封禁
THRESHOLD=5
WINDOW=10

# 自动定位管理脚本路径
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
MANAGE_SCRIPT="$SCRIPT_DIR/manage_xdp.sh"

if [ ! -f "$LOG_FILE" ]; then
    echo "错误: 未找到 Nginx 日志文件 $LOG_FILE"
    exit 1
fi

echo "正在监控 Nginx 日志并自动封禁攻击 IP..."

# 使用 tail -f 实时读取日志
# 这里的逻辑：寻找 404 状态码，提取 IP，计数，封禁
tail -F "$LOG_FILE" | while read line; do
    # 简单的正则提取 IP (假设默认 Nginx 日志格式)
    IP=$(echo "$line" | awk '{print $1}')
    STATUS=$(echo "$line" | awk '{print $9}')

    if [ "$STATUS" == "404" ]; then
        # 记录 IP 到临时文件或内存中进行计数
        # 简单实现：直接调用管理脚本
        # 在生产环境建议使用更复杂的计数逻辑 (如 awk 或 redis)
        echo "[$(date)] 检测到攻击行为来自 $IP (状态码 $STATUS), 正在加入黑名单..."
        "$MANAGE_SCRIPT" add "$IP"
    fi
done
