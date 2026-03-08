CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g
IFLAGS  := -I.

# Detect BPF target arch from the host machine
ARCH    := $(shell uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/')
BPF_ARCH_FLAG := -D__TARGET_ARCH_$(ARCH)

BPF_CFLAGS := $(CFLAGS) -target bpf $(BPF_ARCH_FLAG) $(IFLAGS)
LDFLAGS    := -lbpf -lelf -lz

# ── BPF object targets ────────────────────────────────────────────────────────
BPF_TARGETS := \
	tcp_to_pid/tcp_to_pid.bpf.o \
	sched_wakeup/prob.bpf.o \
	sched_wakeup_new/prob.bpf.o

# ── Userspace object targets ──────────────────────────────────────────────────
US_OBJS := \
	utils/loader.o \
	handlers.o \
	loader.o

.PHONY: all bpf userspace clean

all: bpf userspace

# BPF programs
bpf: $(BPF_TARGETS)

tcp_to_pid/tcp_to_pid.bpf.o: tcp_to_pid/tcp_to_pid.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# prob.bpf.c is the source; output as prob.bpf.o to match the name expected by loader.c
sched_wakeup/prob.bpf.o: sched_wakeup/prob.bpf.c
	$(CLANG) $(BPF_CFLAGS) -I.. -c $< -o $@

sched_wakeup_new/prob.bpf.o: sched_wakeup_new/prob.bpf.c
	$(CLANG) $(BPF_CFLAGS) -I.. -c $< -o $@

# Userspace objects
userspace: $(US_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(IFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_TARGETS) $(US_OBJS)
