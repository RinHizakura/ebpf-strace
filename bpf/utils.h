#ifndef UTILS_H
#define UTILS_H

#define DEFINE_BPF_MAP_NO_ACCESSORS(the_map, map_type, key_type, value_type, \
                                    num_entries)                             \
    struct {                                                                 \
        __uint(type, map_type);                                              \
        __uint(max_entries, (num_entries));                                  \
        __type(key, key_type);                                               \
        __type(value, value_type);                                           \
    } the_map SEC(".maps");

/* Create type safe accessor function for each kind of map */
#define DEFINE_BPF_MAP(the_map, map_type, key_type, value_type, num_entries) \
    DEFINE_BPF_MAP_NO_ACCESSORS(the_map, map_type, key_type, value_type,     \
                                num_entries)                                 \
                                                                             \
    static value_type *bpf_##the_map##_lookup_elem(key_type *k)              \
    {                                                                        \
        return bpf_map_lookup_elem(&the_map, k);                             \
    }                                                                        \
                                                                             \
    static int bpf_##the_map##_update_elem(key_type *k, value_type *v,       \
                                           __u64 flags)                      \
    {                                                                        \
        return bpf_map_update_elem(&the_map, k, v, flags);                   \
    }                                                                        \
                                                                             \
    static int bpf_##the_map##_delete_elem(key_type *k)                      \
    {                                                                        \
        return bpf_map_delete_elem(&the_map, k);                             \
    }

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#endif
