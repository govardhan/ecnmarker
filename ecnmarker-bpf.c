#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

SEC("tc")
int ecnmarker(struct __sk_buff *skb)
{
	// use default action configured from tc
	// BTF does not record #define macros so TC_ACT_* are missing from vmlinux.h
	return -1;	// TC_ACT_UNSPEC
}

char _license[] SEC("license") = "GPL";
