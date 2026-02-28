/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tcp_tracer.h — Shared data structures between the BPF kernel program and
 * the userspace consumer for the TCP span tracer.
 *
 * All fields use fixed-width kernel types so the layout is identical on both
 * sides of the BPF perf-event channel.
 */

#ifndef __TCP_TRACER_H
#define __TCP_TRACER_H

/*
 * Type definitions.
 *
 * When vmlinux.h is included first it already defines __u8/__u16/__u32/__u64,
 * so we must not pull in <linux/types.h> again.  The vmlinux.h header guards
 * itself with __VMLINUX_H__, so we test for that macro.
 * In userspace builds <linux/types.h> provides the kernel-style typedefs and
 * is included transitively by <bpf/libbpf.h>; we include it here as well so
 * that the header is self-contained.
 */
#if defined(__BPF_TRACING__) && defined(__VMLINUX_H__)
/* All types already provided by vmlinux.h — nothing to include. */
#elif defined(__BPF_TRACING__)
/* BPF build without vmlinux.h: use the kernel header directly. */
#include <linux/types.h>
#else
/* Userspace build. */
#include <linux/types.h>
#endif

/* Maximum length of a process name (matches TASK_COMM_LEN in the kernel). */
#define TASK_COMM_LEN 16

/* Event-type tags carried in tcp_event.event_type. */
#define EVENT_TCP_SEND  1   /* kprobe on tcp_sendmsg  — outgoing data */
#define EVENT_TCP_RECV  2   /* kprobe on tcp_recvmsg  — incoming data */
#define EVENT_UPROBE    3   /* uprobe on a user-space function        */

/*
 * tcp_event — one span event emitted from the BPF program to userspace via
 * the perf-event ring buffer.
 *
 * trace_id:    Stable identifier for the end-to-end request flow.  It is
 *              generated when a new inbound TCP read is observed for a PID
 *              and stored in the pid_trace_map BPF hash map.  Subsequent
 *              outbound writes by the same PID carry the same trace_id,
 *              which lets the userspace correlate a downstream TCP send
 *              with the request that triggered it.
 *
 * span_id:     Unique identifier for this individual BPF event / span.
 *
 * pid / tid:   User-space process / thread IDs of the running task.
 *
 * event_type:  One of the EVENT_* constants above.
 *
 * data_len:    Bytes passed to tcp_sendmsg / tcp_recvmsg.
 *
 * saddr/daddr: IPv4 source and destination addresses (network byte order).
 * sport/dport: TCP source and destination ports (host byte order after
 *              conversion in the BPF program).
 *
 * timestamp_ns: ktime_get_ns() value at the moment the probe fired.
 *
 * comm:        Null-terminated name of the process (e.g. "nginx", "curl").
 */
struct tcp_event {
    __u64 trace_id;
    __u64 span_id;
    __u32 pid;
    __u32 tid;
    __u32 event_type;
    __u32 data_len;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 timestamp_ns;
    char  comm[TASK_COMM_LEN];
};

#endif /* __TCP_TRACER_H */
