/* cgroup/skb BPF prog */
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("filter")
int cgroup_socket_drop(struct __sk_buff *skb)
{
    /* analyze skb content here */
    return 0; /* 0 = drop, 1 = forward */
}

char __license[] __section("license") = "GPL";
