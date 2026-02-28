# SPDX-License-Identifier: GPL-2.0
#
# Makefile — build the tcp_tracer eBPF application.
#
# Prerequisites (Ubuntu / Debian):
#   sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
#                           linux-tools-$(uname -r)
#
# Targets:
#   all         — build the BPF object and the userspace binary (default)
#   vmlinux.h   — generate a portable kernel-type header via bpftool
#   clean       — remove generated files
#   help        — print a short usage summary

# ---- Toolchain -----------------------------------------------------------

CLANG      ?= clang
# Prefer the kernel-specific bpftool; fall back to any installed version.
BPFTOOL    ?= $(shell \
    bt=/usr/lib/linux-tools/$$(uname -r)/bpftool; \
    if [ -x "$$bt" ]; then echo "$$bt"; \
    else ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1; fi)
CC         ?= gcc
ARCH       ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# ---- Flags ---------------------------------------------------------------

BPF_CFLAGS  = -g -O2 -target bpf -D__BPF_TRACING__      \
              -D__TARGET_ARCH_$(ARCH)                      \
              -Wall -Wno-unused-value -Wno-pointer-sign  \
              -Wno-compare-distinct-pointer-types         \
              -I/usr/include/bpf                          \
              -I.

CFLAGS     ?= -g -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS    ?= -lbpf -lelf -lz

# ---- Source and output files ---------------------------------------------

BPF_SRC     = ebpf/tcp_tracer.bpf.c
BPF_OBJ     = ebpf/tcp_tracer.bpf.o
VMLINUX_H   = ebpf/vmlinux.h
USER_SRC    = tcp_tracer.c
USER_BIN    = tcp_tracer

.PHONY: all clean help

# ---- Default target ------------------------------------------------------

all: $(USER_BIN)

# ---- Generate vmlinux.h --------------------------------------------------
#
# vmlinux.h provides kernel type definitions for CO-RE (Compile Once – Run
# Everywhere).  It is derived from the running kernel's BTF information and
# must be regenerated whenever the target kernel changes.

$(VMLINUX_H):
	@echo "  GEN     $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ---- Compile BPF kernel program ------------------------------------------

$(BPF_OBJ): $(BPF_SRC) ebpf/tcp_tracer.h $(VMLINUX_H)
	@echo "  BPF CC  $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ---- Compile userspace binary --------------------------------------------

$(USER_BIN): $(USER_SRC) ebpf/tcp_tracer.h $(BPF_OBJ)
	@echo "  CC      $@"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# ---- Clean ---------------------------------------------------------------

clean:
	@echo "  CLEAN"
	rm -f $(BPF_OBJ) $(USER_BIN)
	@# vmlinux.h is kept intentionally; remove with: rm -f $(VMLINUX_H)

# ---- Help ----------------------------------------------------------------

help:
	@echo "Targets:"
	@echo "  all          Build $(USER_BIN) (default)"
	@echo "  $(VMLINUX_H)  Generate kernel-type header from BTF"
	@echo "  clean        Remove build artefacts"
	@echo ""
	@echo "Runtime (requires root / CAP_BPF):"
	@echo "  sudo ./$(USER_BIN)"
	@echo "  sudo ./$(USER_BIN) --uprobe-binary /usr/bin/curl \\"
	@echo "                     --uprobe-sym Curl_senddata"
