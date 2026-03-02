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

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size, int flags, int *addr_len)
{
    u32 key = 0;
    u32 *target_pid;

    struct event *e;

    e = bpf_ringbuf_reserve(&tcp_events, sizeof(*e), 0);

    if (!e)
    {
        return 0;
    }

    target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != *target_pid)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->size = size;

    bpf_ringbuf_submit(e, 0);
    return 0;
}