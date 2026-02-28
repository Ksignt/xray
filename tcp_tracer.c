// SPDX-License-Identifier: GPL-2.0
/*
 * tcp_tracer.c — userspace loader and span-log consumer for the TCP tracer.
 *
 * This program:
 *   1. Generates vmlinux.h (if not already present) and compiles the BPF
 *      kernel program (handled by the Makefile before this binary runs).
 *   2. Loads the pre-compiled BPF object (tcp_tracer.bpf.o) using libbpf.
 *   3. Attaches kprobes to tcp_sendmsg and tcp_recvmsg.
 *   4. Optionally attaches a uprobe to a user-specified binary/symbol pair
 *      (--uprobe-binary and --uprobe-sym flags).
 *   5. Opens a perf-event buffer and, for each event received, prints a
 *      JSON span log to stdout.
 *
 * Usage:
 *   sudo ./tcp_tracer [--uprobe-binary <path>] [--uprobe-sym <symbol>]
 *                     [--uprobe-offset <hex_offset>]
 *
 * The uprobe flags are all optional; omitting them disables the uprobe.
 *
 * Build:
 *   make
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf/tcp_tracer.h"

/* -------------------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------------- */

static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* -------------------------------------------------------------------------
 * Event formatting helpers
 * ---------------------------------------------------------------------- */

static const char *event_type_str(uint32_t type)
{
    switch (type) {
    case EVENT_TCP_SEND: return "tcp_send";
    case EVENT_TCP_RECV: return "tcp_recv";
    case EVENT_UPROBE:   return "uprobe";
    default:             return "unknown";
    }
}

/*
 * ipv4_str — format a network-byte-order IPv4 address into a dotted-decimal
 * string stored in buf (must be at least INET_ADDRSTRLEN bytes long).
 */
static const char *ipv4_str(uint32_t addr, char *buf)
{
    struct in_addr in = { .s_addr = addr };
    inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN);
    return buf;
}

/*
 * print_span — emit one JSON span log to stdout.
 *
 * The schema is intentionally minimal so it can be consumed by any
 * OpenTelemetry-compatible span collector without further conversion.
 */
static void print_span(const struct tcp_event *evt)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ipv4_str(evt->saddr, src);
    ipv4_str(evt->daddr, dst);

    printf("{"
           "\"trace_id\":\"0x%016llx\","
           "\"span_id\":\"0x%016llx\","
           "\"operation\":\"%s\","
           "\"pid\":%u,"
           "\"tid\":%u,"
           "\"comm\":\"%.*s\","
           "\"src\":\"%s:%u\","
           "\"dst\":\"%s:%u\","
           "\"data_len\":%u,"
           "\"timestamp_ns\":%llu"
           "}\n",
           (unsigned long long)evt->trace_id,
           (unsigned long long)evt->span_id,
           event_type_str(evt->event_type),
           evt->pid,
           evt->tid,
           TASK_COMM_LEN, evt->comm,
           src, evt->sport,
           dst, evt->dport,
           evt->data_len,
           (unsigned long long)evt->timestamp_ns);

    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * Perf-buffer callback
 * ---------------------------------------------------------------------- */

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    (void)ctx;
    (void)cpu;

    if (data_sz < sizeof(struct tcp_event)) {
        fprintf(stderr, "warn: short event (%u bytes), skipping\n", data_sz);
        return;
    }

    const struct tcp_event *evt = data;
    print_span(evt);
}

static void handle_lost(void *ctx, int cpu, unsigned long long lost_cnt)
{
    (void)ctx;
    fprintf(stderr, "warn: lost %llu events on CPU %d\n",
            (unsigned long long)lost_cnt, cpu);
}

/* -------------------------------------------------------------------------
 * libbpf log callback (suppress noise by default)
 * ---------------------------------------------------------------------- */

static int libbpf_print(enum libbpf_print_level level,
                        const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;   /* suppress debug messages */
    return vfprintf(stderr, format, args);
}

/* -------------------------------------------------------------------------
 * Uprobe attachment
 * ---------------------------------------------------------------------- */

/*
 * attach_uprobe — attach the BPF "uprobe" program to the function at
 * *symbol* (or *offset* if symbol resolution is unavailable) inside
 * *binary_path*.
 *
 * Returns a non-NULL link on success, NULL on failure (error already
 * printed).
 */
static struct bpf_link *attach_uprobe(struct bpf_object *obj,
                                      const char *binary_path,
                                      const char *symbol,
                                      unsigned long offset)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj,
                                   "trace_uprobe_entry");
    if (!prog) {
        fprintf(stderr, "error: uprobe BPF program not found in object\n");
        return NULL;
    }

    /* Symbol-based attachment is preferred when func_name is non-NULL;
     * offset provides an additional byte offset within the function and is
     * typically 0.  Both are forwarded to bpf_program__attach_uprobe_opts. */
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
                        .func_name = symbol,
                        .retprobe  = false);

    struct bpf_link *link = bpf_program__attach_uprobe_opts(
                                prog,
                                -1,             /* all PIDs */
                                binary_path,
                                offset,
                                &uprobe_opts);
    if (!link) {
        fprintf(stderr, "error: failed to attach uprobe to %s:%s+0x%lx: %s\n",
                binary_path,
                symbol ? symbol : "(none)",
                offset,
                strerror(errno));
        return NULL;
    }

    fprintf(stderr, "info: uprobe attached to %s:%s+0x%lx\n",
            binary_path, symbol ? symbol : "(none)", offset);
    return link;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS]\n"
            "\n"
            "Attaches kprobes to tcp_sendmsg / tcp_recvmsg and emits JSON\n"
            "span logs to stdout.  Each span carries a trace_id that is\n"
            "stable across outbound sends triggered by the same inbound\n"
            "request, enabling causal reconstruction of distributed flows.\n"
            "\n"
            "Options:\n"
            "  --uprobe-binary <path>     Path to the ELF binary to uprobe\n"
            "  --uprobe-sym    <symbol>   Function symbol to uprobe (optional\n"
            "                             if --uprobe-offset is provided)\n"
            "  --uprobe-offset <hex>      Hex byte offset inside binary\n"
            "                             (optional if --uprobe-sym is given)\n"
            "  -h, --help                 Print this help and exit\n"
            "\n"
            "Examples:\n"
            "  sudo ./tcp_tracer\n"
            "  sudo ./tcp_tracer --uprobe-binary /usr/bin/curl \\\n"
            "                    --uprobe-sym Curl_senddata\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *uprobe_binary = NULL;
    const char *uprobe_sym    = NULL;
    unsigned long uprobe_off  = 0;

    static const struct option long_opts[] = {
        { "uprobe-binary", required_argument, NULL, 'b' },
        { "uprobe-sym",    required_argument, NULL, 's' },
        { "uprobe-offset", required_argument, NULL, 'o' },
        { "help",          no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'b': uprobe_binary = optarg;                    break;
        case 's': uprobe_sym    = optarg;                    break;
        case 'o': uprobe_off    = strtoul(optarg, NULL, 16); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* ---- libbpf setup -------------------------------------------------- */
    libbpf_set_print(libbpf_print);

    /* Raise RLIMIT_MEMLOCK so that BPF maps can be locked in memory. */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("warn: setrlimit(RLIMIT_MEMLOCK)");
        /* non-fatal on kernels >= 5.11 that use memcg accounting */
    }

    /* ---- Open the BPF object file -------------------------------------- */
    struct bpf_object *obj = bpf_object__open("ebpf/tcp_tracer.bpf.o");
    if (!obj) {
        fprintf(stderr, "error: failed to open BPF object: %s\n",
                strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "error: failed to load BPF object: %s\n",
                strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    /* ---- Attach kprobe: tcp_sendmsg ------------------------------------ */
    struct bpf_program *send_prog =
        bpf_object__find_program_by_name(obj, "trace_tcp_sendmsg");
    if (!send_prog) {
        fprintf(stderr, "error: trace_tcp_sendmsg program not found\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *send_link = NULL;
    struct bpf_link *recv_link = NULL;

    send_link = bpf_program__attach_kprobe(send_prog, false, "tcp_sendmsg");
    if (!send_link) {
        fprintf(stderr, "error: failed to attach kprobe/tcp_sendmsg: %s\n",
                strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    fprintf(stderr, "info: kprobe attached to tcp_sendmsg\n");

    /* ---- Attach kprobe: tcp_recvmsg ------------------------------------ */
    struct bpf_program *recv_prog =
        bpf_object__find_program_by_name(obj, "trace_tcp_recvmsg");
    if (!recv_prog) {
        fprintf(stderr, "error: trace_tcp_recvmsg program not found\n");
        bpf_link__destroy(send_link);
        bpf_object__close(obj);
        return 1;
    }

    recv_link = bpf_program__attach_kprobe(recv_prog, false, "tcp_recvmsg");
    if (!recv_link) {
        fprintf(stderr, "error: failed to attach kprobe/tcp_recvmsg: %s\n",
                strerror(errno));
        bpf_link__destroy(send_link);
        bpf_object__close(obj);
        return 1;
    }
    fprintf(stderr, "info: kprobe attached to tcp_recvmsg\n");

    /* ---- Optionally attach uprobe -------------------------------------- */
    struct bpf_link *uprobe_link = NULL;
    if (uprobe_binary) {
        uprobe_link = attach_uprobe(obj, uprobe_binary,
                                    uprobe_sym, uprobe_off);
        /* A failed uprobe is a warning, not a fatal error. */
    }

    /* ---- Open the perf-event map --------------------------------------- */
    int events_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (events_fd < 0) {
        fprintf(stderr, "error: events map not found\n");
        goto cleanup;
    }

    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb =
        perf_buffer__new(events_fd, 64 /* pages */,
                         handle_event, handle_lost, NULL, &pb_opts);
    if (!pb) {
        fprintf(stderr, "error: failed to create perf buffer: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /* ---- Main event loop ----------------------------------------------- */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    fprintf(stderr, "info: tracing TCP events… press Ctrl-C to stop\n");

    while (running) {
        int err = perf_buffer__poll(pb, 100 /* timeout ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error: perf_buffer__poll: %s\n",
                    strerror(-err));
            break;
        }
    }

    perf_buffer__free(pb);

cleanup:
    if (uprobe_link)
        bpf_link__destroy(uprobe_link);
    if (recv_link)
        bpf_link__destroy(recv_link);
    if (send_link)
        bpf_link__destroy(send_link);
    bpf_object__close(obj);

    fprintf(stderr, "info: tracer stopped\n");
    return 0;
}
