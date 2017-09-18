#!/usr/bin/env bash
# root required !
IF='eth1'
GW=2017:db8::f1ff

ip r del default
ip -6 r a default via $GW dev $IF
