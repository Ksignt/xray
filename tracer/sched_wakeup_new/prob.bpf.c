#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);

} sched_wakeup_new_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

#include "utils/kernel.h"

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    u32 *target_tid;

    struct sched_wakeup_event *e = bpf_ringbuf_reserve(&sched_wakeup_new_events, sizeof(*e), 0);
    if (!e)
        return 0;

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
    e->prio = BPF_CORE_READ(ctx, prio);
    e->target_cpu = BPF_CORE_READ(ctx, target_cpu);
    BPF_CORE_READ_STR_INTO(&e->comm, ctx, comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
