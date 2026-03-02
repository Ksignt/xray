#ifndef TRACE_GRAPH_EVENT_H
#define TRACE_GRAPH_EVENT_H

struct event
{
    uint32_t pid;
    char comm[16];
    size_t size;
};

#endif
