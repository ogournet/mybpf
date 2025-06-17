#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet


#
# (extremely) simplified cgn scenario, with minimal configuration.
# this script set up environement, netns and ip. to be run once.
#
#
#   in netns cgn-priv                  in netns cgn-pub
# |-------------------|              |---------------------|
# |    priv (veth)    |   <----->    |      pub (veth)     |
# |-------------------|              |---------------------|
#    ip 192.168.61.1 (connected)        ip 192.168.61.2 (connected)
#    ip 10.0.0.1 (simulate a user)      ip 8.8.8.8 (simulate a server)
#
# the same cgn application is loaded on both veth pair.
# here is processing for packets
# - TX on priv iface               IP{ src=10.0.0.1, dst=8.8.8.8 }
# - RX on pub, catched by xdp  
# - XDP inspect/modify packet, create/check flows,
#   then XDP_PASS the result       IP{ src=37.141.0.1 dst=8.8.8.8 }
# - sockets/app/scappy receive packet on pub iface.
#
#
# to run the test, start userapp (will load xdp applications)
#
#  mybpf -i priv@cgn-priv -i pub@cgn-pub cgn_test -t 13
#
# then run python script to send/receive packets:
#
#  ./cgn_run.py ping
#


#set -x

ip netns del cgn-pub 2> /dev/null || true
ip netns del cgn-priv 2> /dev/null || true
ip netns add cgn-pub
ip netns add cgn-priv

ip link add dev pub netns cgn-pub address d2:ad:ca:fe:b4:01 type veth \
   peer name priv netns cgn-priv address d2:f0:0c:ba:a5:00
ip -n cgn-pub link set dev pub up
ip -n cgn-pub link set dev lo up
ip -n cgn-priv link set dev priv up
ip -n cgn-priv link set dev lo up
ip -n cgn-pub addr add 192.168.61.2/24 dev pub
ip -n cgn-pub addr add 8.8.8.8/32 dev pub
ip -n cgn-pub route add 37.141.0.0/24 via 192.168.61.1 dev pub
ip -n cgn-priv addr add 192.168.61.1/24 dev priv
ip -n cgn-priv route add default via 192.168.61.2 dev priv

# this script also serve for ip6fw test
ip -n cgn-pub addr add fc:1::2/64 dev pub
ip -n cgn-pub addr add 2001::8:8:8:8/128 dev pub
ip -n cgn-pub route add 2002::1/16 via fc:1::1 dev pub
ip -n cgn-priv addr add fc:1::1/64 dev priv
ip -n cgn-priv route add default via fc:1::2 dev priv

# fix weird thing with packet checksum sent from a
# classic socket (eg SOCK_DGRAM).
ip netns exec cgn-pub ethtool -K pub tx-checksumming off
ip netns exec cgn-priv ethtool -K priv tx-checksumming off
