#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB

} tcp_events SEC(".maps");

#include "utils/kernel.h"

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size, int flags, int *addr_len)
{
    u32 *target_tid;

    struct event *e;

    e = bpf_ringbuf_reserve(&tcp_events, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }

    target_tid = getTargetPid();
    if (!target_tid)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    u32 tid = getCurrentTid();
    if (tid != *target_tid)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->pid = tid;
    getCurrentComm(e->comm);
    e->size = size;

    bpf_ringbuf_submit(e, 0);
    return 0;
}