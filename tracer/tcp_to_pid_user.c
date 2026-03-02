#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include "event.h"

static volatile sig_atomic_t stop;

void handle_signal(int sig)
{
    stop = 1;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;

    printf("PID=%u COMM=%s size=%lu\n",
           e->pid,
           e->comm,
           e->size);

    return 0;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    int target_pid = 72134;

    signal(SIGINT, handle_signal);

    obj = bpf_object__open_file("tcp_to_pid.bpf.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }
    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "target_pid_map");
    if (map_fd < 0)
    {
        printf("Failed to find map\n");
        return 1;
    }

    uint32_t key = 0;
    if (bpf_map_update_elem(map_fd, &key, &target_pid, BPF_ANY) != 0)
    {
        printf("Failed to update map\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_tcp_recvmsg");
    if (!prog)
    {
        fprintf(stderr, "Failed to find kprobe program\n");
        return 1;
    }
    link = bpf_program__attach(prog);
    if (!link)
    {
        fprintf(stderr, "Failed to attach kprobe\n");
        return 1;
    }

    int rb_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_events");
    if (rb_map_fd < 0)
    {
        printf("Failed to find tcp_events map\n");
        return 1;
    }

    rb = ring_buffer__new(rb_map_fd, handle_event, NULL, NULL);
    if (!rb)
    {
        printf("Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening on tcp_recvmsg... Press Ctrl+C to stop.\n");

    while (!stop)
    {
        ring_buffer__poll(rb, 100);
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}