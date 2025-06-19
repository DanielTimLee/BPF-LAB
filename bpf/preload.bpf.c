#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, 3 /* BPF_MAP_TYPE_PROG_ARRAY */);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 100);
} progs SEC(".maps");

// tail call target
SEC("tp/syscalls/sys_enter_write/target")
int tail_target(void *ctx)
{
	bpf_printk("OK\n");
	return 0;
}
