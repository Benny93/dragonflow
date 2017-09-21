#!/usr/bin/env bash
ovs-vsctl add-br br-ex
ovs-vsctl add-port br-ex p1
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int P1
ovs-vsctl --no-wait set bridge br-int fail-mode=secure other-config:disable-in-band=true
ovs-vsctl set bridge br-int protocols=OpenFlow10,OpenFlow13
ovs-vsctl set-manager ptcp:6640:0.0.0.0