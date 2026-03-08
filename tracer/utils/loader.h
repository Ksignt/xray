#ifndef TRACER_UTILS_LOADER_H
#define TRACER_UTILS_LOADER_H

#include <bpf/libbpf.h>
#include <stdint.h>

struct bpf_object *open_bpf_obj(const char *path);
void load_bpf_obj(struct bpf_object *obj);
struct bpf_object *load_and_get_bpf_obj(const char *path);
struct bpf_link *get_bpf_link(struct bpf_object *obj, const char *msg);
struct ring_buffer *get_ring_buffer_from_map_fd(struct bpf_object *obj, const char *map_name, ring_buffer_sample_fn callback);
void reuse_map_and_update(struct bpf_object *src_obj, const char *map_name, struct bpf_object **dst_objs, int dst_count, uint32_t key, uint32_t value);

#endif
