#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size, int flags, int *addr_len)
{
    // Read the current PID safely
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != 13019) 
    {
        return 0;
    }

    bpf_printk("TCP recvmsg called by PID: %d, size: %lu\n", pid, size);
    return 0;
} 