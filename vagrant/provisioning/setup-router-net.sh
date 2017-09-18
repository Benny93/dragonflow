#!/usr/bin/env bash
# root required !
IP1=2017:db8::f1ff/120
IP2=2017:db8::f2ff/120
IP3=2017:db8::f3ff/120
IF1='eth1'
IF2='eth2'
IF3='eth3'

# make sure adresses are set correctly
ip -6 a a $IP1 dev $IF1
ip l s $IF1 up
ip -6 a a $IP2 dev $IF2
ip l s $IF2 up
ip -6 a a $IP3  dev $IF3
ip l s $IF3 up
#nexthops
sudo ip -6 r a 2017:db8::ffaa nexthop via 2017:db8::f201 dev $IF2 nexthop via 2017:db8::f301 dev $IF3

echo "ROUTER NET SETUP DONE"
