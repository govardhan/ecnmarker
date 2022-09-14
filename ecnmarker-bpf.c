#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

SEC("tc")
int ecnmarker(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	uint16_t ethertype;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) > data_end) {
		bpf_printk("Frame shorter than ethhdr, aborting\n");
		goto out;
	}

	eth = data;
	ethertype = eth->h_proto;

	switch (ethertype) {
		default:
			break;
	}

out:
	// use default action configured from tc
	// BTF does not record #define macros so TC_ACT_* are missing from vmlinux.h
	return -1;	// TC_ACT_UNSPEC
}

char _license[] SEC("license") = "GPL";
