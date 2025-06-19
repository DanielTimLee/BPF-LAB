#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, 3 /* BPF_MAP_TYPE_PROG_ARRAY */);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 100);
} progs SEC(".maps");

/* BPF program type should not matter */
SEC("tp/syscalls/sys_enter_write")
int tp_outbound(void *ctx) {
	__u32 key = 111;
	bpf_tail_call(ctx, &progs, key);
	return 0;
}
