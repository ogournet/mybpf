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
