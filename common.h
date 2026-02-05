#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

/* 配置 Map 的索引 */
#define SETTING_ENABLE_IPV4 0
#define SETTING_ENABLE_IPV6 1
#define SETTING_MAX_ENTRIES  2
#define SETTING_MAX          3

/* 统计 Map 的索引 */
#define STATS_IPV4_PASS 0
#define STATS_IPV4_DROP 1
#define STATS_IPV6_PASS 2
#define STATS_IPV6_DROP 3
#define STATS_MAX       4

/* 尾调用 Map 的索引 */
#define PROG_MODULE_IPV4    0
#define PROG_MODULE_IPV6    1
#define PROG_MODULE_CUSTOM1 2
#define PROG_MODULE_MAX     3

/* 默认 Map 大小 */
#define MAX_BLACKLIST_ENTRIES 10240
#define MAX_LPM_ENTRIES       4096

/* LPM Trie Key 结构 */
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
};

struct lpm_v6_key {
    __u32 prefixlen;
    unsigned char addr[16];
};

/* IPv6 地址结构 */
struct ipv6_addr {
    unsigned char addr[16];
};

/* 拦截事件结构 (用于 Ring Buffer) */
struct event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  action; // 1: DROP, 0: PASS
    __u8  family; // 4 or 6
    __u8  _pad;
};

#endif
