#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet


fail() {
    echo $*;
    exit 1;
}

set -x

send_py_pkt() {
    ns=$1
    port=$2
    script_head="
#!/usr/bin/env python3
from scapy.all import *
"
    script_tail="
[ sendp(i, iface=\"$port\") for i in p ]
"
    if [ -n "$ns" ]; then
	ip netns exec $ns python3 -c "$script_head $3 $script_tail"
    else
	python3 -c "$script_head $3 $script_tail"
    fi
}

send_py_pkt_dis() {
    return
}


# test env for ipfrag
setup_ipfrag() {
    ip netns del test-bpf 2> /dev/null || true
    ip netns add test-bpf

    ip link add dev bpf-main address d2:ad:ca:fe:b4:10 type veth \
       peer name bpf-prg netns test-bpf address d2:f0:0c:ba:a5:10
    ip link set dev bpf-main up
    ip -n test-bpf link set dev bpf-prg up
    ip -n test-bpf link set dev lo up
    ip addr add 192.168.62.1/24 dev bpf-main
    ip -n test-bpf addr add 192.168.62.2/24 dev bpf-prg

    # do not forget to run an xdp_pass program on the other side
    # of the veth !!!
    #./mybpf -i bpf-main pass
}

# ipfrag test.
# use scapy to generate out-of-order fragmented ip packets.
run_ipfrag() {
    # send out-of-order
    send_py_pkt '' bpf-main '
p = [Ether(dst="d2:f0:0c:ba:a5:10", src="d2:ad:ca:fe:b4:10") /
	 IP(src="192.168.62.1", dst="192.168.62.2", id=159) /
	 ICMP(type="echo-request") / ("B" + "a" * 1800 + "E") ]
p = fragment(p)
p.insert(0, p.pop(1))'
}


action=${1:-unset}

case $action in
    setup_ipfrag) setup_ipfrag ;;
    run_ipfrag) run_ipfrag ;;
    ipfrag) setup_ipfrag; run_ipfrag ;;

    *) fail "action '$action' not recognized" ;;
esac
