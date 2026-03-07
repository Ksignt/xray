#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include "loader.h"

struct bpf_object *open_bpf_obj(const char *path)
{
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF object file: %s\n", path);
        exit(1);
    }
    return obj;
}

void load_bpf_obj(struct bpf_object *obj)
{
    int err = bpf_object__load(obj);
    if (err)
    {
        bpf_object__close(obj);
        fprintf(stderr, "Failed to load BPF object\n");
        exit(1);
    }
}

struct bpf_object *load_and_get_bpf_obj(const char *path)
{
    struct bpf_object *obj = open_bpf_obj(path);
    load_bpf_obj(obj);
    return obj;
}

void reuse_map_and_update(struct bpf_object *src_obj, const char *map_name, struct bpf_object **dst_objs, int dst_count, uint32_t key, uint32_t value)
{
    int map_fd = bpf_object__find_map_fd_by_name(src_obj, map_name);
    if (map_fd < 0)
    {
        fprintf(stderr, "Failed to find map '%s' in source object\n", map_name);
        exit(1);
    }

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0)
    {
        fprintf(stderr, "Failed to update map '%s' (fd=%d) with key %u\n", map_name, map_fd, key);
        exit(1);
    }

    for (int i = 0; i < dst_count; i++)
    {
        struct bpf_object *dobj = dst_objs[i];
        if (!dobj)
        {
            fprintf(stderr, "Null destination object at index %d\n", i);
            exit(1);
        }

        struct bpf_map *dst_map = bpf_object__find_map_by_name(dobj, map_name);
        if (!dst_map)
        {
            fprintf(stderr, "Failed to find map '%s' in destination object index %d\n", map_name, i);
            exit(1);
        }

        if (bpf_map__reuse_fd(dst_map, map_fd) != 0)
        {
            fprintf(stderr, "Failed to reuse fd for map '%s' in destination object index %d\n", map_name, i);
            exit(1);
        }
    }
}

struct bpf_link *get_bpf_link(struct bpf_object *obj, const char *msg)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, msg);
    if (!prog)
    {
        fprintf(stderr, "Failed to find %s program\n", msg);
        exit(1);
    }
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link)
    {
        fprintf(stderr, "Failed to attach kprobe\n");
        exit(1);
    }
    return link;
}

struct ring_buffer *get_ring_buffer_from_map_fd(struct bpf_object *obj, const char *map_name, ring_buffer_sample_fn callback)
{
    int rb_map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
    if (rb_map_fd < 0)
    {
        fprintf(stderr, "Failed to find map: %s\n", map_name);
        exit(1);
    }
    struct ring_buffer *rb = ring_buffer__new(rb_map_fd, callback, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        exit(1);
    }
    return rb;
}
