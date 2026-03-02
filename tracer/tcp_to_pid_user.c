#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop;

void handle_signal(int sig)
{
    stop = 1;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

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

    printf("Listening on tcp_recvmsg... Press Ctrl+C to stop.\n");
    while (!stop)
    {
        sleep(1);
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}