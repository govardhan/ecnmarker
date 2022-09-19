#include "vmlinux.h"

#include <bpf/bpf_endian.h>
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

bool check_data(void *data, void *data_end, size_t offset)
{
	if (data + offset > data_end)
		return 1;

	return 0;
}

void handle_ipv4_packet(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (check_data(data, data_end, sizeof(struct ethhdr) + sizeof(struct iphdr))) {
		bpf_printk("IPv4 packet shorter than iphdr, aborting\n");
		return;
	}

	struct iphdr *iph = data + sizeof(struct ethhdr);
	uint8_t ipproto = iph->protocol;

	bpf_printk("IPv4 protocol: %u\n", ipproto);
}

void handle_ipv6_packet(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (check_data(data, data_end, sizeof(struct ethhdr) + sizeof(struct ipv6hdr))) {
		bpf_printk("IPv6 packet shorter than ipv6hdr, aborting\n");
		return;
	}

	struct ipv6hdr *iph = data + sizeof(struct ethhdr);
	uint8_t ipproto = iph->nexthdr;

	bpf_printk("IPv6 protocol: %u\n", ipproto);
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

	if (check_data(data, data_end, sizeof(struct ethhdr))) {
		bpf_printk("Frame shorter than ethhdr, aborting\n");
		goto out;
	}

	eth = data;
	ethertype = eth->h_proto;

	switch (ethertype) {
		case bpf_htons(0x0800):	/* ETH_P_IP */
			handle_ipv4_packet(skb);
			break;
		case bpf_htons(0x86dd):	/* ETH_P_IPV6 */
			handle_ipv6_packet(skb);
			break;
		default:
			break;
	}

out:
	// use default action configured from tc
	// BTF does not record #define macros so TC_ACT_* are missing from vmlinux.h
	return -1;	// TC_ACT_UNSPEC
}

char _license[] SEC("license") = "GPL";
