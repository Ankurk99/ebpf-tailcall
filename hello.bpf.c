// +build ignore
#include "hello.bpf.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 8,
};

#define PROG 1

SEC("kprobe/1")
int bpf_func_PROG(struct pt_regs *ctx)
{
	bpf_printk("World\n");
	return 0;
}

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
	bpf_printk("Hello");
	bpf_tail_call(ctx, &jmp_table, PROG);
	return 0;
}

