#ifndef TRACER_UTILS_KERNEL_H
#define TRACER_UTILS_KERNEL_H

/* Helpers that operate on target_pid_map.
 * The including BPF file must define target_pid_map and pull in
 * vmlinux.h + bpf_helpers.h before including this header. */

static __always_inline u32 *getTargetPid()
{
    u32 k = 0;
    return bpf_map_lookup_elem(&target_pid_map, &k);
}

static __always_inline u32 getCurrentTGid()
{
    return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline u32 getCurrentTid()
{
    return bpf_get_current_pid_tgid() & 0xffffffff;
}

static __always_inline void getCurrentComm(char comm[TASK_COMM_LEN])
{
    bpf_get_current_comm(comm, TASK_COMM_LEN);
}

#endif /* TRACER_UTILS_KERNEL_H */
