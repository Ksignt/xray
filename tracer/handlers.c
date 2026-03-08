#include <stdio.h>
#include "event.h"

#define LOG_FILE "/var/log/trace-graph-engine.log"

static FILE *log_fp = NULL;

static FILE *get_log_file(void)
{
    if (!log_fp)
        log_fp = fopen(LOG_FILE, "a");
    return log_fp;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    FILE *f = get_log_file();
    if (!f) return 0;

    fprintf(f, "TCP_TO_PID: PID=%u COMM=%s size=%lu\n",
            e->pid,
            e->comm,
            e->size);
    fflush(f);
    return 0;
}

int handle_sched_event(void *ctx, void *data, size_t data_sz)
{
    struct sched_wakeup_event *e = data;
    if (!e) return 0;
    FILE *f = get_log_file();
    if (!f) return 0;

    fprintf(f, "SCHED_WAKEUP: PID=%d COMM=%s prio=%d cpu=%d\n",
            e->pid,
            e->comm,
            e->prio,
            e->target_cpu);
    fflush(f);
    return 0;
}
