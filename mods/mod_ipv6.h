#ifndef __MOD_IPV6_H
#define __MOD_IPV6_H

#ifdef ENABLE_IPV6

#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

/* IPv6 黑名单 Map (单个 IP) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __type(key, struct ipv6_addr);
    __type(value, __u8);
} blacklist_v6 SEC(".maps");

/* IPv6 网段黑名单 Map (LPM Trie) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_LPM_ENTRIES);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_v6_lpm SEC(".maps");

/* handle_ipv6 逻辑 */
static __always_inline void log_blocked_ipv6(struct xdp_md *ctx, struct ipv6hdr *ip6h, void *data_end) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->family = 6;
    e->protocol = ip6h->nexthdr;
    e->action = 1;

    void *next = (void *)(ip6h + 1);
    if (ip6h->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = next;
        if ((void *)(tcp + 1) <= data_end) {
            e->src_port = bpf_ntohs(tcp->source);
            e->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = next;
        if ((void *)(udp + 1) <= data_end) {
            e->src_port = bpf_ntohs(udp->source);
            e->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int handle_ipv6(struct xdp_md *ctx, void *data_start, void *data_end) {
    struct ipv6hdr *ip6h = data_start;
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;

    /* 1. 先匹配单个 IP */
    struct ipv6_addr src_ip6;
    __builtin_memcpy(&src_ip6.addr, &ip6h->saddr, sizeof(src_ip6.addr));
    
    __u8 *value = bpf_map_lookup_elem(&blacklist_v6, &src_ip6);
    if (value) {
        log_blocked_ipv6(ctx, ip6h, data_end);
        return XDP_DROP;
    }

    /* 2. 再匹配网段 (LPM) */
    struct lpm_v6_key lpm_key = {
        .prefixlen = 128
    };
    __builtin_memcpy(&lpm_key.addr, &ip6h->saddr, 16);
    value = bpf_map_lookup_elem(&blacklist_v6_lpm, &lpm_key);
    if (value) {
        log_blocked_ipv6(ctx, ip6h, data_end);
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif /* ENABLE_IPV6 */

#endif
