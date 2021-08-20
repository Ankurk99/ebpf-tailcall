// +build ignore
#include "hello.bpf.h"

struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 32,
};

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
	u32 id = 1;
	bpf_printk("Hello");
	bpf_tail_call(ctx, &jmp_table, id);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
