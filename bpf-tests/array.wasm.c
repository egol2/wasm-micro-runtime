#include <stdint.h>

typedef uint32_t __u32;
typedef uint64_t __u64;

#define __uint(name, val)
#define __type(name, type)
#define SEC(x) __attribute__((section(x)))

#define BPF_MAP_TYPE_ARRAY 0
#define BPF_ANY          0

static __u32 ar[256] = { 0 };

void *bpf_map_lookup_elem(void *map, const void *key);
int bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);


int array(void *ctx)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&ar, &key);
    if (!val) {
        return -1;
    } else {
        __u32 new_val = (*val) + 1;
        bpf_map_update_elem(&ar, &key, &new_val, BPF_ANY);
    }
    return 0;
}
