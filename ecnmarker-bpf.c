#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, uint32_t);
	__type(value, uint8_t);
	__uint(max_entries, 1);
} ecnmarker_enabled SEC(".maps");

uint8_t enabled(void)
{
	uint8_t *enabled;
	uint32_t key = 0;

	enabled = bpf_map_lookup_elem(&ecnmarker_enabled, &key);

	if (enabled)
		return *enabled;
	else
		return false;
}

SEC("tc")
int ecnmarker(struct __sk_buff *skb)
{
	if (!enabled()) {
		bpf_printk("ecnmarker disabled\n");
		goto out;
	}

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
