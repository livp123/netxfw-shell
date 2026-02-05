#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/libxdp.h>

#include "common.h"

#include <sys/stat.h>
#include <sys/types.h>

#define PIN_BASE_DIR "/sys/fs/bpf/netxfw-shell"

static void usage(const char *prog) {
    fprintf(stderr, "用法: %s <action> [args]\n", prog);
    fprintf(stderr, "Actions:\n");
    fprintf(stderr, "  load <ifname> [ipv6_on|ipv6_off] [max_entries]\n");
    fprintf(stderr, "  unload <ifname>\n");
    fprintf(stderr, "  add <ip_addr>\n");
    fprintf(stderr, "  del <ip_addr>\n");
    fprintf(stderr, "  config <ipv4|ipv6> <0|1>\n");
    fprintf(stderr, "  plugin <obj_file> <slot_id>\n");
    fprintf(stderr, "  stats\n");
    fprintf(stderr, "  monitor\n");
}

static int open_map(const char *name);

/* 动态加载插件到指定的 Tail Call Slot */
static int do_plugin(const char *obj_file, int slot_id) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, table_fd;
    int err;

    /* 1. 打开并加载插件 BPF 对象 */
    obj = bpf_object__open(obj_file);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "错误: 无法打开插件对象 %s\n", obj_file);
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "错误: 无法加载插件对象: %s\n", strerror(-err));
        return -1;
    }

    /* 2. 获取插件程序的 FD */
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "错误: 插件对象中没有发现程序\n");
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    /* 3. 打开主程序的 jump_table Map */
    table_fd = open_map("jump_table");
    if (table_fd < 0) return -1;

    /* 4. 将插件 FD 更新到 Slot */
    __u32 key = slot_id;
    err = bpf_map_update_elem(table_fd, &key, &prog_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "错误: 无法更新 jump_table: %s\n", strerror(errno));
        close(table_fd);
        return -1;
    }

    printf("成功将插件 %s 加载到 Slot %d\n", obj_file, slot_id);
    close(table_fd);
    return 0;
}

/* 辅助函数：打开挂载的 Map */
static int open_map(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_BASE_DIR, name);
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "错误: 无法打开 Map %s: %s\n", name, strerror(errno));
    }
    return fd;
}

/* 加载 XDP 程序 */
static int do_load(const char *ifname, int ipv6_enabled, __u32 max_entries) {
    struct xdp_program *prog;
    struct bpf_object *obj;
    int ifindex = if_nametoindex(ifname);
    int err;

    if (ifindex == 0) {
        fprintf(stderr, "错误: 无效的接口名 %s\n", ifname);
        return -1;
    }

    /* 1. 打开 BPF 对象 */
    obj = bpf_object__open("xdp_blacklist.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "错误: 无法打开 BPF 对象\n");
        return -1;
    }

    /* 2. 动态设置 Map 大小 */
    struct bpf_map *map_v4 = bpf_object__find_map_by_name(obj, "blacklist_v4");
    if (map_v4 && max_entries > 0) {
        bpf_map__set_max_entries(map_v4, max_entries);
    }
    
    struct bpf_map *map_v6 = bpf_object__find_map_by_name(obj, "blacklist_v6");
    if (map_v6 && max_entries > 0) {
        bpf_map__set_max_entries(map_v6, max_entries);
    }

    /* 3. 加载到内核 */
    /* 确保挂载目录干净且存在 */
    char cleanup_cmd[256];
    snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf %s && mkdir -p %s", PIN_BASE_DIR, PIN_BASE_DIR);
    system(cleanup_cmd);

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "错误: 无法加载 BPF 对象: %s\n", strerror(-err));
        return -1;
    }

    /* 4. 挂载所有 Map 到指定目录 */
    err = bpf_object__pin_maps(obj, PIN_BASE_DIR);
    if (err) {
        fprintf(stderr, "错误: 无法挂载 Maps 到 %s: %s\n", PIN_BASE_DIR, strerror(-err));
        return -1;
    }

    /* 5. 初始化配置 */
    int settings_fd = bpf_object__find_map_fd_by_name(obj, "settings");
    if (settings_fd >= 0) {
        __u32 key_v4 = SETTING_ENABLE_IPV4;
        __u32 val_v4 = 1;
        bpf_map_update_elem(settings_fd, &key_v4, &val_v4, BPF_ANY);

        __u32 key_v6 = SETTING_ENABLE_IPV6;
        __u32 val_v6 = ipv6_enabled ? 1 : 0;
        bpf_map_update_elem(settings_fd, &key_v6, &val_v6, BPF_ANY);
        
        __u32 key_max = SETTING_MAX_ENTRIES;
        bpf_map_update_elem(settings_fd, &key_max, &max_entries, BPF_ANY);
    }

    /* 6. 查找程序并尝试多种模式挂载 (HW -> Native -> SKB) */
    prog = xdp_program__from_bpf_obj(obj, "xdp");
    if (!prog) {
        fprintf(stderr, "错误: 找不到 XDP 程序\n");
        return -1;
    }

    enum xdp_attach_mode modes[] = {XDP_MODE_HW, XDP_MODE_NATIVE, XDP_MODE_SKB};
    const char *mode_names[] = {"Offload (HW)", "Native (DRV)", "Generic (SKB)"};
    int attached = 0;

    for (int i = 0; i < 3; i++) {
        err = xdp_program__attach(prog, ifindex, modes[i], 0);
        if (err == 0) {
            printf("成功加载 XDP 防火墙到 %s (模式: %s, IPv6: %s, MaxEntries: %u)\n", 
                   ifname, mode_names[i], ipv6_enabled ? "ON" : "OFF", max_entries);
            attached = 1;
            break;
        } else {
            fprintf(stderr, "提示: 无法以 %s 模式挂载: %s，尝试降级...\n", 
                    mode_names[i], strerror(-err));
        }
    }

    if (!attached) {
        fprintf(stderr, "错误: 所有挂载模式均失败\n");
        return -1;
    }

    return 0;
}

/* 卸载 XDP 程序 */
static int do_unload(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return -1;

    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);
    if (!mp) {
        printf("接口 %s 上没有发现 XDP 程序\n", ifname);
    } else {
        int err = xdp_multiprog__detach(mp);
        xdp_multiprog__close(mp);

        if (err) {
            fprintf(stderr, "错误: 无法卸载 XDP 程序: %s\n", strerror(-err));
            return -1;
        }
        printf("成功从 %s 卸载 XDP 防火墙\n", ifname);
    }

    /* 无论接口上是否有程序，都尝试清理挂载目录 */
    printf("正在清理 BPF Map 挂载目录 %s...\n", PIN_BASE_DIR);
    
    /* 遍历并删除目录下的文件 */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", PIN_BASE_DIR);
    if (system(cmd) == 0) {
        printf("清理完成。\n");
    } else {
        fprintf(stderr, "警告: 无法完全清理 %s，请检查权限。\n", PIN_BASE_DIR);
    }

    return 0;
}

/* 显示统计信息 */
static void do_stats() {
    int fd = open_map("stats_map");
    if (fd < 0) return;

    __u64 values[libbpf_num_possible_cpus()];
    const char *names[] = {"IPv4 Pass", "IPv4 Drop", "IPv6 Pass", "IPv6 Drop"};
    
    printf("\n--- XDP Firewall Statistics ---\n");
    for (__u32 i = 0; i < STATS_MAX; i++) {
        if (bpf_map_lookup_elem(fd, &i, values) != 0) continue;
        
        __u64 total = 0;
        for (int c = 0; c < libbpf_num_possible_cpus(); c++) {
            total += values[c];
        }
        printf("%-10s : %llu\n", names[i], total);
    }
    printf("-------------------------------\n");
    close(fd);
}

/* 添加/删除黑名单 */
static int do_manage_ip(const char *ip_str, int add) {
    struct in_addr addr4;
    struct in6_addr addr6;
    char *slash = strchr(ip_str, '/');
    int prefixlen = -1;
    char ip_only[INET6_ADDRSTRLEN];

    if (slash) {
        prefixlen = atoi(slash + 1);
        size_t len = slash - ip_str;
        if (len >= sizeof(ip_only)) len = sizeof(ip_only) - 1;
        strncpy(ip_only, ip_str, len);
        ip_only[len] = '\0';
    } else {
        strncpy(ip_only, ip_str, sizeof(ip_only));
    }

    if (inet_pton(AF_INET, ip_only, &addr4) == 1) {
        if (prefixlen != -1) {
            /* 处理 IPv4 网段 (LPM) */
            int fd = open_map("blacklist_v4_lpm");
            if (fd < 0) return -1;
            struct lpm_v4_key key = { .prefixlen = prefixlen, .addr = addr4.s_addr };
            if (add) {
                __u8 val = 1;
                bpf_map_update_elem(fd, &key, &val, BPF_ANY);
                printf("已添加 IPv4 网段到黑名单: %s\n", ip_str);
            } else {
                bpf_map_delete_elem(fd, &key);
                printf("已从黑名单删除 IPv4 网段: %s\n", ip_str);
            }
            close(fd);
        } else {
            /* 处理单个 IPv4 (Hash) */
            int fd = open_map("blacklist_v4");
            if (fd < 0) return -1;
            __u32 key = addr4.s_addr;
            if (add) {
                __u8 val = 1;
                bpf_map_update_elem(fd, &key, &val, BPF_ANY);
                printf("已添加 IPv4 到黑名单: %s\n", ip_str);
            } else {
                bpf_map_delete_elem(fd, &key);
                printf("已从黑名单删除 IPv4: %s\n", ip_str);
            }
            close(fd);
        }
    } else if (inet_pton(AF_INET6, ip_only, &addr6) == 1) {
        if (prefixlen != -1) {
            /* 处理 IPv6 网段 (LPM) */
            int fd = open_map("blacklist_v6_lpm");
            if (fd < 0) return -1;
            struct lpm_v6_key key = { .prefixlen = prefixlen };
            memcpy(key.addr, &addr6, 16);
            if (add) {
                __u8 val = 1;
                bpf_map_update_elem(fd, &key, &val, BPF_ANY);
                printf("已添加 IPv6 网段到黑名单: %s\n", ip_str);
            } else {
                bpf_map_delete_elem(fd, &key);
                printf("已从黑名单删除 IPv6 网段: %s\n", ip_str);
            }
            close(fd);
        } else {
            /* 处理单个 IPv6 (Hash) */
            int fd = open_map("blacklist_v6");
            if (fd < 0) return -1;
            struct ipv6_addr key;
            memcpy(key.addr, &addr6, 16);
            if (add) {
                __u8 val = 1;
                bpf_map_update_elem(fd, &key, &val, BPF_ANY);
                printf("已添加 IPv6 到黑名单: %s\n", ip_str);
            } else {
                bpf_map_delete_elem(fd, &key);
                printf("已从黑名单删除 IPv6: %s\n", ip_str);
            }
            close(fd);
        }
    } else {
        fprintf(stderr, "错误: 无效的 IP 地址或网段 %s\n", ip_str);
        return -1;
    }

    return 0;
}

/* 运行时配置 */
static int do_config(const char *type, int val) {
    int fd = open_map("settings");
    if (fd < 0) return -1;

    __u32 key;
    if (strcmp(type, "ipv4") == 0) key = SETTING_ENABLE_IPV4;
    else if (strcmp(type, "ipv6") == 0) key = SETTING_ENABLE_IPV6;
    else {
        fprintf(stderr, "错误: 未知的配置项 %s\n", type);
        close(fd);
        return -1;
    }

    if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        close(fd);
        return -1;
    }

    printf("配置已更新: %s = %d\n", type, val);
    close(fd);
    return 0;
}

/* 处理 Ring Buffer 事件的回调函数 */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    const char *proto_str = "UNKNOWN";

    if (e->family == 4) {
        struct in_addr src = { .s_addr = e->src_ip };
        struct in_addr dst = { .s_addr = e->dst_ip };
        inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));
    } else {
        // IPv6 简化显示
        snprintf(src_ip, sizeof(src_ip), "IPv6_ADDR");
        snprintf(dst_ip, sizeof(dst_ip), "IPv6_ADDR");
    }

    if (e->protocol == IPPROTO_TCP) proto_str = "TCP";
    else if (e->protocol == IPPROTO_UDP) proto_str = "UDP";
    else if (e->protocol == IPPROTO_ICMP) proto_str = "ICMP";

    printf("[BLOCK] %s:%u -> %s:%u (%s)\n", 
           src_ip, e->src_port, dst_ip, e->dst_port, proto_str);
    
    return 0;
}

/* 监听拦截日志 */
static int do_monitor() {
    int fd = open_map("rb");
    if (fd < 0) return -1;

    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "错误: 无法创建 Ring Buffer 实例\n");
        close(fd);
        return -1;
    }

    printf("正在监控拦截日志 (Ctrl+C 退出)...\n");
    while (1) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];

    if (strcmp(action, "load") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        int ipv6 = (argc > 3 && strcmp(argv[3], "ipv6_on") == 0);
        __u32 max = (argc > 4) ? atoi(argv[4]) : MAX_BLACKLIST_ENTRIES;
        return do_load(argv[2], ipv6, max);
    } else if (strcmp(action, "unload") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return do_unload(argv[2]);
    } else if (strcmp(action, "add") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return do_manage_ip(argv[2], 1);
    } else if (strcmp(action, "del") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return do_manage_ip(argv[2], 0);
    } else if (strcmp(action, "config") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return do_config(argv[2], atoi(argv[3]));
    } else if (strcmp(action, "plugin") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return do_plugin(argv[2], atoi(argv[3]));
    } else if (strcmp(action, "stats") == 0) {
        do_stats();
        return 0;
    } else if (strcmp(action, "monitor") == 0) {
        return do_monitor();
    } else {
        usage(argv[0]);
        return 1;
    }
}
