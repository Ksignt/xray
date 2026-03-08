#ifndef HANDLERS_H
#define HANDLERS_H

#include <stddef.h>

int handle_event(void *ctx, void *data, size_t data_sz);
int handle_sched_wakeup_event(void *ctx, void *data, size_t data_sz);
int handle_sched_wakeup_new_event(void *ctx, void *data, size_t data_sz);

#endif
