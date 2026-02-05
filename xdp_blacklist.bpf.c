#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* 配置 Map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SETTING_MAX);
    __type(key, __u32);
    __type(value, __u32);
} settings SEC(".maps");

/* 尾调用 Map */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, PROG_MODULE_MAX);
    __type(key, __u32);
    __type(value, __u32);
} jump_table SEC(".maps");

/* 统计 Map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* 拦截日志 Ring Buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256 KB
} rb SEC(".maps");

/* 包含模块逻辑 - 注意：模块内会用到上面定义的 rb 和 settings */
#include "mod_ipv4.h"
#include "mod_ipv6.h"

static __always_inline void count_stats(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        *val += 1;
    }
}

SEC("xdp")
int xdp_firewall_shell(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    int rc = XDP_PASS;

    /* 1. 执行模块化逻辑 (带 Fast Path 优化) */
    if (h_proto == ETH_P_IP) {
        __u32 key = SETTING_ENABLE_IPV4;
        __u32 *enabled = bpf_map_lookup_elem(&settings, &key);
        if (!enabled || *enabled) {
            rc = handle_ipv4(ctx, eth + 1, data_end);
            if (rc == XDP_DROP) {
                count_stats(STATS_IPV4_DROP);
                return XDP_DROP;
            }
            count_stats(STATS_IPV4_PASS);
        }
    } 
#ifdef ENABLE_IPV6
    else if (h_proto == ETH_P_IPV6) {
        __u32 key = SETTING_ENABLE_IPV6;
        __u32 *enabled = bpf_map_lookup_elem(&settings, &key);
        if (!enabled || *enabled) {
            rc = handle_ipv6(ctx, eth + 1, data_end);
            if (rc == XDP_DROP) {
                count_stats(STATS_IPV6_DROP);
                return XDP_DROP;
            }
            count_stats(STATS_IPV6_PASS);
        }
    }
#endif

    /* 2. 动态扩展入口 (尾调用) */
    bpf_tail_call(ctx, &jump_table, PROG_MODULE_CUSTOM1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
