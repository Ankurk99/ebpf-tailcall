// +build ignore
#include "hello.bpf.h"
#include <linux/bpf.h>


struct bpf_map_def SEC("maps") progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 3,
}

PROG(world) 
{
	bpf_printk("World\n");
	return 0;
}

SEC("kprobe/sys_execve")
int hello(void *ctx) 
{
	bpf_printk("Hello");
	bpf_tail_call(ctx, &prog, world);
	return 0;
}
