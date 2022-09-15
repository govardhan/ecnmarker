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

# Enable/disable bpf program
The bpf program uses a map with a single value to check if it should run.
The value of this map can be changed with bpftool:
```
bpftool map update name ecnmarker_enabl key 0 0 0 0 value 1
```
A value greater than 0 will enable the program.
