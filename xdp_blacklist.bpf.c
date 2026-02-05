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



SEC("xdp")
int xdp_firewall_shell(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    
    // 早期协议验证 - 仅处理 IPv4 和 IPv6
    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
        return XDP_PASS;

    int rc = XDP_PASS;

    /* 1. 执行模块化逻辑 (带 Fast Path 优化) */
    if (h_proto == ETH_P_IP) {
        __u32 key = SETTING_ENABLE_IPV4;
        __u32 *enabled = bpf_map_lookup_elem(&settings, &key);
        if (!enabled || *enabled) {
            rc = handle_ipv4(ctx, eth + 1, data_end);
            if (rc == XDP_DROP) {
                __u32 stat_key = STATS_IPV4_DROP;
                __u64 *val = bpf_map_lookup_elem(&stats_map, &stat_key);
                if (val) {
                    *val += 1;
                }
                return XDP_DROP;
            }
            __u32 stat_key_pass = STATS_IPV4_PASS;
            __u64 *val_pass = bpf_map_lookup_elem(&stats_map, &stat_key_pass);
            if (val_pass) {
                *val_pass += 1;
            }
        }
    } 
#ifdef ENABLE_IPV6
    else if (h_proto == ETH_P_IPV6) {
        __u32 key = SETTING_ENABLE_IPV6;
        __u32 *enabled = bpf_map_lookup_elem(&settings, &key);
        if (!enabled || *enabled) {
            rc = handle_ipv6(ctx, eth + 1, data_end);
            if (rc == XDP_DROP) {
                __u32 stat_key = STATS_IPV6_DROP;
                __u64 *val = bpf_map_lookup_elem(&stats_map, &stat_key);
                if (val) {
                    *val += 1;
                }
                return XDP_DROP;
            }
            __u32 stat_key_pass = STATS_IPV6_PASS;
            __u64 *val_pass = bpf_map_lookup_elem(&stats_map, &stat_key_pass);
            if (val_pass) {
                *val_pass += 1;
            }
        }
    }
#endif

    /* 2. 动态扩展入口 (尾调用) - 仅当有附加模块时才执行 */
    __u32 tail_call_key = PROG_MODULE_CUSTOM1;
    __u32 *prog_fd = bpf_map_lookup_elem(&jump_table, &tail_call_key);
    if (prog_fd) {
        bpf_tail_call(ctx, &jump_table, PROG_MODULE_CUSTOM1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
