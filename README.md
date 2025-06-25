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


### cgn test:

see `test/cgn_setup.sh` for instructions.


# cgn notes

A few NAT implementation already exists in eBPF
- [cilium](https://github.com/cilium/cilium), see bpf/lib/nat.h
- [einat-ebpf](https://github.com/EHfive/einat-ebpf) but there is no
CGN (Carrier Grade NAT) implementation in eBPF to my knowledge.

Keypoints:
  - network is clearly divided into 'private' network,
    consisting of users/customers (eg. mobile subscribers), and 'public'
    network, which is the whole internet.
	the CGN sits, like a firewall, between these two networks.
  - one user equals one 'private' ip (usually in the 10.0.0.0/8 range,
    but not mandatory)
  - everything can pass from private to public, but only 'established'
    trafic can pass from public to private.
  - localhost (CGN server) is not a 'NAT user', and only forward
    trafic. speaking iptables, it only uses FORWARD, not INPUT or
    OUTPUT tables. from eBPF pov, only an XDP on eth RX is needed.
  - ip/ports allocation from a 'big' ipv4 pool. Anything from /16 to
    /32, instead of a single 'masquerade' ip.
  - ports are allocated in block (from 32k to 10 ports). for usual
    NAT, port is (randomly) allocated one by one.
  - log block allocation (lawful)

Todo list:
  - more tests
  - improve cli, to be able to check user/block/flows status
  - add ip fragmentation handling
  - add 'hairpin', to handle STUN correctly
