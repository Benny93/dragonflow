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


CTLR_IP = '127.0.0.1'
CTLR_PRT = '6653'

# 0: Step wise testing, 1: Continues Testing
mode = 1


def stop_net(controller, cname, switch):
    info("*** Stopping network\n")
    controller.cmd('kill %' + cname)
    switch.cmd('ovs-vsctl del-br dp0')
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
    switch.cmd('ovs-vsctl del-br dp0')
    switch.cmd('ovs-vsctl add-br dp0')
    for intf in switch.intfs.values():
        print switch.cmd('ovs-vsctl add-port dp0 %s' % intf)

    # Note: controller and switch are in root namespace, and we
    # can connect via loopback interface
    s_cmd = 'ovs-vsctl set-controller dp0 tcp:{}:{}'.format(CTLR_IP, CTLR_PRT)
    print s_cmd
    switch.cmd(s_cmd)
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
        file_name = 'pings_{}_{}_{}-{}_{}_{}.csv'.format(dt.tm_year, dt.tm_mon, dt.tm_mday, tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec)
        f = open(file_name, 'w+')
        for item in ping_results:
            f.write(item)
        stop_net(controller, cname, switch)


def step_wise_testing(h0, h1, ping_results):
    while True:
        if 'is_connected' not in quietRun('ovs-vsctl show'):
            wait_for_controller_connection()
        print "Press ENTER to execute Test\n"
        line = sys.stdin.readline()
        if line:
            info("Key Input Accepted\n")

        ping_test(h0, h1, ping_results)


def continuous_testing(h0, h1, ping_results):
    while True:
        if 'is_connected' not in quietRun('ovs-vsctl show'):
            wait_for_controller_connection()
        ping_test(h0, h1, ping_results)
        time.sleep(1)


def ping_test(h0, h1, ping_results):
    info("*** Running test\n")
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
    while 'is_connected' not in quietRun('ovs-vsctl show'):
        time.sleep(1)
        info('.')
    info('Connected \n')


if __name__ == '__main__':
    setLogLevel('info')
    info('*** Scratch network demo (kernel datapath)\n')
    Mininet.init()
    scratchNet()
