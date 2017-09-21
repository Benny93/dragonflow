#!/usr/bin/python

"""
Build a simple network from scratch, using mininet primitives.
This is more complicated than using the higher-level classes,
but it exposes the configuration details and allows customization.

For most tasks, the higher-level API will be preferable.
"""
import csv
import sys
import time
from mininet.net import Mininet
from mininet.node import Node
from mininet.link import Link
from mininet.log import setLogLevel, info
from mininet.util import quietRun
import pingparser
import re

CTLR_IP = '127.0.0.1'
CTLR_PRT = '6653'

# 0: Step wise testing, 1: Continuous Testing
mode = 1
ctl_connect_pattern = ""


def stop_net(controller, cname, switch):
    info("*** Stopping network\n")
    controller.cmd('kill %' + cname)
    switch.cmd('ovs-vsctl del-br br-int')
    #switch.cmd('ovs-vsctl del-br br-ex')
    switch.deleteIntfs()
    info('Net was removed\n')


def scratchNet(cname='controller', cargs='-v ptcp:'):
    "Create network from scratch using Open vSwitch."

    info("*** Creating nodes\n")
    controller = Node('c0', inNamespace=False)
    switch = Node('s0', inNamespace=False)
    h0 = Node('h0')
    h1 = Node('h1')

    info("*** Creating links\n")
    Link(h0, switch)
    Link(h1, switch)

    info("*** Configuring hosts\n")
    h0.setIP('192.168.123.1/24')
    h1.setIP('192.168.123.2/24')
    info(str(h0) + '\n')
    info(str(h1) + '\n')

    info("*** Starting network using Open vSwitch\n")
    controller.cmd(cname + ' ' + cargs + '&')

    #issue_switch_cmd(switch, 'ovs-vsctl del-br br-ex')
    issue_switch_cmd(switch, 'ovs-vsctl del-br br-int')
    #issue_switch_cmd(switch, 'ovs-vsctl add-br br-ex')
    issue_switch_cmd(switch, 'ovs-vsctl add-br br-int')

    # CONCLUSION
    # ovs-vsctl add-br br-ex
    # ovs-vsctl add-port br-ex {external_nic}
    # ovs-vsctl add-br br-int
    # ovs-vsctl add-port br-int {internal_nic}
    # ovs-vsctl --no-wait set bridge br-int fail-mode=secure other-config:disable-in-band=true
    # ovs-vsctl set bridge br-int protocols=OpenFlow10,OpenFlow13
    # ovs-vsctl set-manager ptcp:6640:0.0.0.0

    for intf in switch.intfs.values():
        print issue_switch_cmd(switch, 'ovs-vsctl add-port br-int %s' % intf)

    # for intf in switch.intfs.values():
    #    print issue_switch_cmd(switch, 'ovs-vsctl add-port br-ex %s' % intf)

    issue_switch_cmd(switch, 'ovs-vsctl --no-wait set bridge br-int fail-mode=secure other-config:disable-in-band=true')
    issue_switch_cmd(switch, 'ovs-vsctl set bridge br-int protocols=OpenFlow10,OpenFlow13')
    #issue_switch_cmd(switch, 'ovs-vsctl set-manager ptcp:6640:0.0.0.0')
    # issue_switch_cmd(switch, 'ovs-ofctl -O OpenFlow13  dump-flows br-int')

    # Note: controller and switch are in root namespace, and we
    # can connect via loopback interface
    s_cmd = 'ovs-vsctl set-controller br-int tcp:{}:{}'.format(CTLR_IP, CTLR_PRT)
    issue_switch_cmd(switch, s_cmd)

    ping_results = ['received,host,jitter,packet_loss,avgping,minping,time,sent,maxping\n']
    try:
        h0.cmd('echo "" > pings.txt')
        if mode == 0:
            step_wise_testing(h0, h1, ping_results)
        else:
            continuous_testing(h0, h1, ping_results)
    except KeyboardInterrupt:
        print "Warning: Caught KeyboardInterrupt, stopping network"
        tm_local = time.localtime()
        dt = time.gmtime()
        file_name = 'pings_{}_{}_{}-{}_{}_{}.csv'.format(dt.tm_year, dt.tm_mon, dt.tm_mday, tm_local.tm_hour,
                                                         tm_local.tm_min, tm_local.tm_sec)
        f = open(file_name, 'w+')
        for item in ping_results:
            f.write(item)
        stop_net(controller, cname, switch)


def issue_switch_cmd(switch, cmd):
    print cmd
    print switch.cmd(cmd)


def step_wise_testing(h0, h1, ping_results):
    while True:
        if not ctl_connect_pattern.match(quietRun('ovs-vsctl show')):
            wait_for_controller_connection()
        print "Press ENTER to execute Test\n"
        line = sys.stdin.readline()
        if line:
            info("Key Input Accepted\n")

        ping_test(h0, h1, ping_results)


def continuous_testing(h0, h1, ping_results):
    while True:
        if not ctl_connect_pattern.match(quietRun('ovs-vsctl show')):
            wait_for_controller_connection()
        ping_test(h0, h1, ping_results)
        time.sleep(1)


def ping_test(h0, h1, ping_results):
    info("*** Running test\n")
    info("Arp Table of h0\n")
    print h0.cmdPrint("arp -n")
    ping_res = h0.cmdPrint('ping -c1 ' + h1.IP())
    ping_res = pingparser.parse(ping_res)
    tm_local = time.localtime()
    ping_res['time'] = '{}:{}:{}'.format(tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec)
    val_string = ','.join(ping_res.itervalues())
    ping_results.append(val_string + "\n")

    print ping_res
    info("*** Sleep\n")


def wait_for_controller_connection():
    info('*** Waiting for switch to connect to controller')
    # while 'is_connected' not in quietRun('ovs-vsctl show'):
    while not ctl_connect_pattern.match(quietRun('ovs-vsctl show')):
        time.sleep(1)
        info('.')
    info('Connected \n')


if __name__ == '__main__':
    ctl_connect_pattern = re.compile(r".+Controller.+\n.+is_connected\: true.+", re.DOTALL)
    setLogLevel('info')
    info('*** Scratch network demo (kernel datapath)\n')
    Mininet.init()
    scratchNet()
