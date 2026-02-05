BPF_OBJ = xdp_blacklist.bpf.o
PLUGIN_OBJ = mods/plugin_port_block.bpf.o
LOADER = xdp_loader
MODS_DIR = mods

# 默认启用 IPv6 编译
ENABLE_IPV6 ?= 1

CFLAGS = -O2 -g
BPF_CFLAGS = -I. -I$(MODS_DIR)

ifeq ($(ENABLE_IPV6), 1)
	BPF_CFLAGS += -DENABLE_IPV6
endif

# 链接 libbpf 和 libxdp
LIBS = -lxdp -lbpf -lelf -lz

all: $(BPF_OBJ) $(PLUGIN_OBJ) $(LOADER)

plugins: $(PLUGIN_OBJ)

$(BPF_OBJ): xdp_blacklist.bpf.c $(MODS_DIR)/*.h common.h
	clang $(CFLAGS) -target bpf $(BPF_CFLAGS) -c -o $@ $<

$(PLUGIN_OBJ): mods/plugin_port_block.bpf.c common.h
	clang $(CFLAGS) -target bpf $(BPF_CFLAGS) -c -o $@ $<

$(LOADER): xdp_loader.c common.h
	gcc $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BPF_OBJ) $(PLUGIN_OBJ) $(LOADER)

.PHONY: all clean
