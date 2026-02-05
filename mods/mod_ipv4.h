#ifndef __MOD_IPV4_H
#define __MOD_IPV4_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

/* IPv4 黑名单 Map (单个 IP) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blacklist_v4 SEC(".maps");

/* IPv4 网段黑名单 Map (LPM Trie) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_LPM_ENTRIES);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blacklist_v4_lpm SEC(".maps");

/* handle_ipv4 逻辑 */
static __always_inline void log_blocked_ipv4(struct xdp_md *ctx, struct iphdr *iph, void *data_end) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->protocol = iph->protocol;
    e->family = 4;
    e->action = 1;

    void *next = (void *)iph + (iph->ihl * 4);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = next;
        if ((void *)(tcp + 1) <= data_end) {
            e->src_port = bpf_ntohs(tcp->source);
            e->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = next;
        if ((void *)(udp + 1) <= data_end) {
            e->src_port = bpf_ntohs(udp->source);
            e->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int handle_ipv4(struct xdp_md *ctx, void *data_start, void *data_end) {
    struct iphdr *iph = data_start;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    /* 1. 先匹配单个 IP */
    __u8 *value = bpf_map_lookup_elem(&blacklist_v4, &src_ip);
    if (value) {
        log_blocked_ipv4(ctx, iph, data_end);
        return XDP_DROP;
    }

    /* 2. 再匹配网段 (LPM) */
    struct lpm_v4_key lpm_key = {
        .prefixlen = 32,
        .addr = src_ip
    };
    value = bpf_map_lookup_elem(&blacklist_v4_lpm, &lpm_key);
    if (value) {
        log_blocked_ipv4(ctx, iph, data_end);
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif
