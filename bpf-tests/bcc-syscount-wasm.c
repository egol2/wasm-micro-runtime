#include <stdint.h>
#include <stdbool.h>

typedef uint32_t __u32;
typedef uint32_t u32;
typedef uint64_t __u64;
typedef uint64_t u64;

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 8192
#define BPF_NOEXIST 1
#define	EEXIST 17

struct data_t {
	__u64 count;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
};

const volatile bool filter_cg = false;
const volatile bool count_by_process = false;
const volatile bool measure_latency = false;
const volatile bool filter_failed = false;
const volatile int filter_errno = false;
const volatile int filter_pid = 0;

// struct {
// 	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
// 	__type(key, u32);
// 	__type(value, u32);
// 	__uint(max_entries, 1);
// } cgroup_map SEC(".maps");

static __u32 cgroup_map[MAX_ENTRIES] = { 0 };


// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, u32);
// 	__type(value, u64);
// } start SEC(".maps");

static __u32 start[MAX_ENTRIES] = { 0 };

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, u32);
// 	__type(value, struct data_t);
// } data SEC(".maps");

static __u32 data[MAX_ENTRIES] = { 0 };

void *bpf_map_lookup_elem(void *map, const void *key);
int bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);

// BPF_CALL_2(bpf_current_task_under_cgroup, struct bpf_map *, map, u32, idx)
// {
// 	struct bpf_array *array = container_of(map, struct bpf_array, map);
// 	struct cgroup *cgrp;

// 	if (unlikely(idx >= array->map.max_entries))
// 		return -E2BIG;

// 	cgrp = READ_ONCE(array->ptrs[idx]);
// 	if (unlikely(!cgrp))
// 		return -EAGAIN;

// 	return task_under_cgroup_hierarchy(current, cgrp);
// }
//

u64 bpf_current_task_under_cgroup(void *map, u32 idx);

// BPF_CALL_0(bpf_get_current_task)
// {
// 	return (long) current;
// }

long bpf_get_current_task();

// BPF_CALL_0(bpf_get_current_pid_tgid)
// {
// 	struct task_struct *task = current;

// 	if (unlikely(!task))
// 		return -EINVAL;

// 	return (u64) task->tgid << 32 | task->pid;
// }
//

u64 bpf_get_current_pid_tgid();

// BPF_CALL_0(bpf_ktime_get_ns)
// {
// 	/* NMI safe access to clock monotonic */
// 	return ktime_get_mono_fast_ns();
// }

u64 bpf_ktime_get_ns();

// BPF_CALL_3(bpf_probe_read_kernel_str, void *, dst, u32, size,
// 	   const void *, unsafe_ptr)
// {
//     return bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr);
// }
//
int bpf_probe_read_kernel_str(void *dst, u32 size, const void* unsafe_ptr);

static inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
		return 0;

	return bpf_map_lookup_elem(map, key);
}

static inline
void save_proc_name(struct data_t *val)
{
	struct task_struct *current = (void *)bpf_get_current_task();

	/* We should save the process name every time because it can be
	 * changed (e.g., by exec).  This can be optimized later by managing
	 * this field with the help of tp/sched/sched_process_exec and
	 * raw_tp/task_rename. */
	//BPF_CORE_READ_STR_INTO(&val->comm, current, group_leader, comm);
	bpf_probe_read_kernel_str(&val->comm, 32, current);
}

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};

int sys_exit(struct trace_event_raw_sys_exit *args)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	static const struct data_t zero;
	int pid = id >> 32;
	struct data_t *val;
	u64 *start_ts, lat = 0;
	u32 tid = id;
	u32 key;

	/* this happens when there is an interrupt */
	if (args->id == -1)
		return 0;

	if (filter_pid && pid != filter_pid)
		return 0;
	if (filter_failed && args->ret >= 0)
		return 0;
	if (filter_errno && args->ret != -filter_errno)
		return 0;

	if (measure_latency) {
		start_ts = bpf_map_lookup_elem(&start, &tid);
		if (!start_ts)
			return 0;
		lat = bpf_ktime_get_ns() - *start_ts;
	}

	key = (count_by_process) ? pid : args->id;
	val = bpf_map_lookup_or_try_init(&data, &key, &zero);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
		if (count_by_process)
			save_proc_name(val);
		if (measure_latency)
			__sync_fetch_and_add(&val->total_ns, lat);
	}
	return 0;
}
