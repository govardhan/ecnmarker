# Attach the bpf program to a clsact qdisc
```
export IFACE="eno1"

tc qdisc add dev "$IFACE" clsact
tc filter add dev "$IFACE" egress prio 0x100 bpf object-file /lib/ecnmarker/ecnmarker-bpf.o sec tc verbose direct-action
```

# Verify
```
tc filter show dev "$IFACE" egress
```
