#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import sys
import os
import socket
from scapy.all import *
from pyroute2 import netns


def check_cksum(r, proto):
    assert r.haslayer(proto)
    old_l4_csum = r.getlayer(proto).chksum
    old_l3_csum = r[IP].chksum
    r[proto].chksum = None
    r[IP].chksum = None
    rr = Ether(raw(r))  # scapy will recompute checksums
    assert old_l4_csum == rr.getlayer(proto).chksum
    assert old_l3_csum == rr[IP].chksum

def run_on_both_side(fn_pub, fn_priv):
    val = os.fork()
    if val == 0:
        netns.setns('cgn-pub')
        fn_pub()
    else:
        netns.setns('cgn-priv')
        fn_priv()

    
#######

def test_ping_pong(iface):
    # send ping
    p = Ether(src="d2:f0:0c:ba:a5:00", dst="d2:ad:ca:fe:b4:01") / \
    IP(src="10.0.0.1", dst="8.8.8.8", id=159) / \
    ICMP(type="echo-request", id=59) / \
    ("B" + "a" * 100 + "E")
    r = srp1(p, iface=iface, verbose=0, timeout=2)
    assert r != None

    # check we received a pong
    assert r[ICMP].code == 0 and r[ICMP].type == 0
    assert r[IP].ttl == 63
    assert r[ICMP].id == p[ICMP].id and r[ICMP].seq == p[ICMP].seq
    check_cksum(r, "ICMP")

    # send a second ping, check
    p[ICMP].seq += 1
    r2 = srp1(p, iface=iface, verbose=0, timeout=2)
    assert r2 != None
    check_cksum(r2, "ICMP")
    print("ping test ok")

    
#######

def test_icmp_err():
    # send udp on closed port
    p = Ether(src="d2:f0:0c:ba:a5:00", dst="d2:ad:ca:fe:b4:01") / \
    IP(src="10.0.0.1", dst="8.8.8.8", id=159) / \
    UDP(sport=35000, dport=80) / \
    ("GET /something HTTP/1.0")
    r = srp1(p, iface="priv", verbose=0, timeout=2)
    assert r != None
    check_cksum(r, "ICMP")
    print("icmp err test ok")


#######

def pub_test_udp():
    fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fd.bind(('8.8.8.8', 99))
    data, remote = fd.recvfrom(1024)
    fd.sendto(data, remote)
    fd.close()

def priv_test_udp():
    p = Ether(src="d2:f0:0c:ba:a5:00", dst="d2:ad:ca:fe:b4:01") / \
    IP(src="10.0.0.1", dst="8.8.8.8") / \
    UDP(sport=2000, dport=99) / ("DATADATA")

    r = srp1(p, iface="priv", verbose=0, timeout=2)
    check_cksum(r, "UDP")
    print("test udp finished")



    
match sys.argv[1] if len(sys.argv) > 1 else "":
    case "ping":
        netns.setns('cgn-priv')
        test_ping_pong("priv")
    case "icmp-err":
        netns.setns('cgn-priv')
        test_icmp_err()
    case "udp":
        run_on_both_side(pub_test_udp, priv_test_udp)
    case _:
        print("give me a valid command!")
