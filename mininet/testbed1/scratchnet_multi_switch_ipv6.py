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
from mininet.node import Node, Controller
from mininet.link import Link
from mininet.log import setLogLevel, info
from mininet.util import quietRun
from mininet.node import RemoteController
import pingparser
from mininet.cli import CLI

CTLR_IP = '2017:db8::ffaa'
CTLR_PRT = '6633'


def stop_switch(switch):
    info("*** Stopping network\n")
    switch.cmd('ovs-vsctl del-br {}'.format(switch.name))
    switch.deleteIntfs()
    info('Net was removed\n')

class FakeController(Controller):
     def __init__(self, name, inNamespace=False, command='controller',
                  cargs='-v ptcp:%d', cdir=None, ip="127.0.0.1",
                  port=6653, protocol='tcp', **params ):
         self.command = command
         self.cargs = cargs
         self.cdir = cdir
         self.ip = ip
         self.port = port
         self.protocol = protocol
         Node.__init__(self, name, inNamespace=inNamespace,
                       ip=ip, **params)

     def start(self):
         "Overridden to do nothing."
         return

     def stop(self):
         "Overridden to do nothing."
         return


def scratchNet(cname='controller', cargs='-v ptcp:'):
    "Create network from scratch using Open vSwitch."

    info("*** Creating nodes\n")
    # s1 = Node('s1', inNamespace=False)
    # s2 = Node('s2', inNamespace=False)
    # s3 = Node('s3', inNamespace=False)
    # s_legacy = Node('s0', inNamespace=False)
    #
    # h1 = Node('h1')
    # h2 = Node('h2')
    # h3 = Node('h3')

    #h1.setMAC(mac='01:00:00:00:01:00')
    #h1.setMAC(mac='01:00:00:00:02:00')
    #h1.setMAC(mac='01:00:00:00:03:00')

    net = Mininet(topo=None, build=False)


    # Create nodes
    h1 = net.addHost('h1', mac='01:00:00:00:01:00', ip='192.168.33.10/24', defaultRoute="via 192.168.33.1")
    h2 = net.addHost('h2', mac='01:00:00:00:02:00', ip='192.168.34.10/24', defaultRoute="via 192.168.34.1")
    h3 = net.addHost('h3', mac='01:00:00:00:03:00', ip='192.168.33.11/24', defaultRoute="via 192.168.33.1")
    # h1 = net.addHost('h1', mac='01:00:00:00:01:00', ip='192.168.33.10/24')
    # h2 = net.addHost('h2', mac='01:00:00:00:02:00', ip='192.168.34.10/24')


    # Create switches
    s1 = net.addSwitch('s1', listenPort=int(CTLR_PRT), mac='00:00:00:00:00:01')
    s2 = net.addSwitch('s2', listenPort=int(CTLR_PRT), mac='00:00:00:00:00:02')
    s3 = net.addSwitch('s3', listenPort=int(CTLR_PRT), mac='00:00:00:00:00:03')

    # non sdn switch to enable multiple hosts behind a port.
    s10 = net.addSwitch('s10', protocols='OpenFlow13', failMode='standalone')

    info("*** Creating links\n")
    # Link(h1, s_legacy)
    # Link(h3, s_legacy)
    # Link(s_legacy, s1)
    # Link(s1, s2)
    # Link(s2, s3)
    # Link(s3, h2)

    net.addLink(h1, s10, )
    net.addLink(h3, s10, )
    net.addLink(s10, s1)
    net.addLink(s1, s2, )
    net.addLink(s2, s3, )
    net.addLink(h2, s3, )

    # Create controller access
    #c0 = net.addController('c0', controller=RemoteController, ip='[{}]'.format(CTLR_IP), port=int(CTLR_PRT))
    c0 = FakeController(name='c0', ip='[{}]'.format(CTLR_IP), port=int(CTLR_PRT))
    #c1 = net.addController('c1', controller=RemoteController, ip='[{}]'.format(CTLR_IP), port=int(CTLR_PRT))


    #info("*** Configuring hosts\n")
    # h1.setIP('192.168.33.10/24')
    # h3.setIP('192.168.33.11/24')
    # h2.setIP('192.168.34.10/24')
    #
    # info(str(h1) + '\n')
    # info(str(h2) + '\n')
    #
    # info("*** Starting network using Open vSwitch\n")
    # start_switch(s1, datapath_id=1)
    # start_switch(s2, datapath_id=2)
    # start_switch(s3, datapath_id=3)
    # start_legacy_switch(s_legacy)


    net.build()
    stime = 3

    s1.start([c0])
    print "sleeping{}".format(stime)
    time.sleep(stime)
    s2.start([c0])
    print "sleeping{}".format(stime)
    time.sleep(stime)
    s3.start([c0])


    #print s1.cmd('ovs-vsctl set-controller {} tcp:[{}]:{}'.format(s1.name, CTLR_IP, CTLR_PRT))

    s10.start([])

    s1.cmdPrint('ovs-vsctl show')
    CLI(net)
    #print "Ping h2 from h1"
    #try:
    #     while True:
    #         print h1.cmd('ping -c1 %s' % h2.IP())
    #         time.sleep(1)
    # except KeyboardInterrupt:
    #     print "\nWarning: Caught KeyboardInterrupt, stopping network"
    #     net.stop()
    net.stop()

    # try:
    #     continuous_testing(h1, h3)
    # except KeyboardInterrupt:
    #     print "Warning: Caught KeyboardInterrupt, stopping network"
    #     stop_switch(s1)
    #     stop_switch(s2)
    #     stop_switch(s3)
    #     #stop_switch(s_legacy)


def start_switch(switch, datapath_id):
    print "Name of switch {}".format(switch.name)
    switch.cmd('ovs-vsctl del-br {}'.format(switch.name))
    print switch.cmd('ovs-vsctl add-br {}'.format(switch.name))

    for intf in switch.intfs.values():
        print switch.cmd('ovs-vsctl add-port {} {}'.format(switch.name, intf))

    print switch.cmd('ovs-vsctl set bridge {}  other-config:datapath-id={}'.format(switch.name, datapath_id))
    read_dp = switch.cmd('ovs-vsctl get Bridge {} other-config:datapath-id'.format(switch.name))
    print "Datapath id is: {}".format(read_dp)


    # Note: controller and s1 are in root namespace, and we
    # can connect via loopback interface
    s_cmd = 'ovs-vsctl set-controller {} tcp:[{}]:{}'.format(switch.name, CTLR_IP, CTLR_PRT)
    print s_cmd
    switch.cmd(s_cmd)


def start_legacy_switch(switch):
    switch.cmd('ovs-vsctl del-br {}'.format(switch.name))
    switch.cmd('ovs-vsctl add-br {}'.format(switch.name))

    for intf in switch.intfs.values():
        print switch.cmd('ovs-vsctl add-port {} {}'.format(switch.name, intf))

    s_cmd = 'ovs-vsctl set-fail-mode {} standalone'.format(switch.name)
    print s_cmd
    switch.cmd(s_cmd)

def start_switch2(switch, controllers):
        """Start OpenFlow reference user datapath.
           Log to /tmp/sN-{ofd,ofp}.log.
           controllers: list of controller objects"""
        # Add controllers
        clist = ','.join(['tcp:%s:%d' % (c.ip, c.port)
                          for c in controllers])
        ofdlog = '/tmp/' + switch.name + '-ofd.log'
        ofplog = '/tmp/' + switch.name + '-ofp.log'
        intfs = [str(i) for i in switch.intfList() if not i.IP()]
        switch.cmd('ofdatapath -i ' + ','.join(intfs) +
                 ' punix:/tmp/' + switch.name + ' -d %s ' % switch.dpid +
                   switch.dpopts +
                 ' 1> ' + ofdlog + ' 2> ' + ofdlog + ' &')
        switch.cmd('ofprotocol unix:/tmp/' + switch.name +
                 ' ' + clist +
                 ' --fail=closed ' + switch.opts +
                 ' 1> ' + ofplog + ' 2>' + ofplog + ' &')


def continuous_testing(h0, h1):
    while True:
        if 'is_connected' not in quietRun('ovs-vsctl show'):
            wait_for_controller_connection()
        ping_test(h0, h1)
        time.sleep(1)


def ping_test(h0, h1):
    info("*** Running test\n")
    ping_res = h0.cmdPrint('ping -c1 ' + h1.IP())
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
    #Mininet.init()
    scratchNet()
