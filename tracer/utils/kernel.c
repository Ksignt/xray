#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include <bpf/bpf_core_read.h>
#include "event.h"

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} target_pid_map SEC(".maps");

u32 key = 0;

static __always_inline u32 *getTargetPid()
{
	return bpf_map_lookup_elem(&target_pid_map, &key);
}

static __always_inline u32 getCurrentTGid()
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline u32 getCurrentTid()
{
	bpf_get_current_pid_tgid() & 0xffffffff;
}

static __always_inline void getCurrentComm(char comm[TASK_COMM_LEN])
{
    bpf_get_current_comm(comm, TASK_COMM_LEN);
}