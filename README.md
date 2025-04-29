# mybpf: personal eBPF playground

a collection of some little program to check ebpf/xdp features, for my own training plan.


# Build

note that you will need fairly recent distribution (at the time of writting).
tested on debian trixie (13), with kernel 6.12 and libbpf 1.5.
older versions may not work.

install dependencies:
```
apt-get install libbpf-dev bpftool libxdp-dev libev-dev meson
```

build:
```
make
```


# Run tests

in a first terminal, start userspace program
```
sudo ./build/mybpf <program>
```

in a second, you may check bpf_printk output (if any)
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

and in a third, send some packets. by default, xdp program is loaded on `lo`
```
ping 127.0.0.1
```

see sources for more details on programs.


### pkt_queue test:

setup is:

```
sudo ip netns add test-bpf
sudo ip link add dev bpf1 type veth peer name bpf2 netns test-bpf
sudo ip link set dev bpf1 up
sudo ip -n test-bpf link set dev bpf2 up
sudo ip addr add 192.168.62.1/24 dev bpf1
sudo ip -n test-bpf addr add 192.168.62.2/24 dev bpf2

# in a first terminal
ip netns exec test-bpf ./build/mybpf -i bpf2 pkt_queue

# in a second terminal
ping -c 1 192.168.62.2
# ping should complete with a delay
```


### ipfrag test:

setup is:

```
sudo ./test/ipfrag.sh setup_ipfrag
sudo ./build/mybpf -i bpf-main pass

# in another terminal
sudo ip netns exec test-bpf ./build/mybpf -i bpf-prg ipfrag

# in a third terminal
sudo ./test/ipfrag.sh run_ipfrag
```
