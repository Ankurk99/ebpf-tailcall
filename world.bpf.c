// +build ignore
#include "hello.bpf.h"

SEC("kprobe/sub_sys_execve")
int world(void *ctx)
{
    bpf_printk("World!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
