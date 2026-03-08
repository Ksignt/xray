#ifndef TRACE_GRAPH_EVENT_H
#define TRACE_GRAPH_EVENT_H

#ifndef __BPF__
#include <stdint.h>
typedef uint32_t u32;
#endif

struct event
{
    uint32_t pid;
    char comm[16];
    size_t size;
};

struct sched_wakeup_event
{
    uint32_t pid;
    int prio;
    int target_cpu;
    char comm[16];
};

#endif
