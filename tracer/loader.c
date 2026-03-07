#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include <stdlib.h>
#include "event.h"
#include "handlers.h"
#include "utils/loader.h"

void handle_signal(int sig);
void clean_up_listeners();

static volatile sig_atomic_t stop;
#define BPF_PROG_MAX_SIZE 20

static struct bpf_link *links[BPF_PROG_MAX_SIZE] = {0};
static struct bpf_object *objs[BPF_PROG_MAX_SIZE] = {0};
static struct ring_buffer *rbs[BPF_PROG_MAX_SIZE] = {0};
int success_bpf_link_count = 0;
int success_bpf_obj_count = 0;
int success_rb_count = 0;

int load_probes(int target_pid)
{
    atexit(clean_up_listeners);
    signal(SIGINT, handle_signal);

    struct bpf_object *tcp_to_pid_obj = load_and_get_bpf_obj("./tracer/tcp_to_pid/tcp_to_pid.bpf.o");
    if (success_bpf_obj_count >= BPF_PROG_MAX_SIZE) { fprintf(stderr, "Too many BPF objects\n"); exit(1); }
    objs[success_bpf_obj_count++] = tcp_to_pid_obj;

    struct bpf_object *sched_wake_up_obj = open_bpf_obj("./tracer/sched_wakeup/prob.bpf.o");
    if (success_bpf_obj_count >= BPF_PROG_MAX_SIZE) { fprintf(stderr, "Too many BPF objects\n"); exit(1); }
    objs[success_bpf_obj_count++] = sched_wake_up_obj;

    reuse_map_and_update(objs[0], "target_pid_map", &objs[1], success_bpf_obj_count - 1, 0, (uint32_t)target_pid);

    load_bpf_obj(sched_wake_up_obj);

    struct bpf_link *tcp_to_pid_link = get_bpf_link(tcp_to_pid_obj, "handle_tcp_recvmsg");
    if (success_bpf_link_count >= BPF_PROG_MAX_SIZE) { fprintf(stderr, "Too many BPF links\n"); exit(1); }
    links[success_bpf_link_count++] = tcp_to_pid_link;
    struct bpf_link *sched_wakeup_link = get_bpf_link(sched_wake_up_obj, "handle_sched_wakeup");
    if (success_bpf_link_count >= BPF_PROG_MAX_SIZE) { fprintf(stderr, "Too many BPF links\n"); exit(1); }
    links[success_bpf_link_count++] = sched_wakeup_link;

    struct ring_buffer *tcp_to_pid_rb = get_ring_buffer_from_map_fd(tcp_to_pid_obj, "tcp_events", handle_event);
    if (success_rb_count >= BPF_PROG_MAX_SIZE) { fprintf(stderr, "Too many ring buffers\n"); exit(1); }
    rbs[success_rb_count++] = tcp_to_pid_rb;
    struct ring_buffer *sched_wake_up_rb = get_ring_buffer_from_map_fd(sched_wake_up_obj, "sched_wakeup_events", handle_sched_event);
    if (success_rb_count >= BPF_PROG_MAX_SIZE) { fprintf(stderr, "Too many ring buffers\n"); exit(1); }
    rbs[success_rb_count++] = sched_wake_up_rb;

    printf("Listening on tcp_recvmsg... Press Ctrl+C to stop.\n");

    while (!stop)
    {
        ring_buffer__poll(tcp_to_pid_rb, 100);
        ring_buffer__poll(sched_wake_up_rb, 100);
    }

    return 0;
}

void handle_signal(int sig)
{
    stop = 1;
}

void clean_up_listeners()
{
    for (int i = 0; i < success_bpf_link_count; i++)
    {
        if (links[i])
            bpf_link__destroy(links[i]);
    }

    for (int i = 0; i < success_rb_count; i++)
    {
        if (rbs[i])
            ring_buffer__free(rbs[i]);
    }

    for (int i = 0; i < success_bpf_obj_count; i++)
    {
        if (objs[i])
            bpf_object__close(objs[i]);
    }
}
