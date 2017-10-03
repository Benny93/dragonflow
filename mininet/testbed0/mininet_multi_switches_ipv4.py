#!/usr/bin/python
"""Custom topology example

      default subnet          |          diffrent subnet
                              |
   n host --- n switch --- switch  --- n switch --- n host

"""
import time
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI

def Main():
    setLogLevel('info')
    net = Mininet(topo=None, build=False)


    # Create nodes
    h1 = net.addHost('h1', mac='01:00:00:00:01:00', ip='192.168.33.10/24', defaultRoute="via 192.168.33.1")
    h2 = net.addHost('h2', mac='01:00:00:00:02:00', ip='192.168.34.10/24', defaultRoute="via 192.168.34.1")
    # h1 = net.addHost('h1', mac='01:00:00:00:01:00', ip='192.168.33.10/24')
    # h2 = net.addHost('h2', mac='01:00:00:00:02:00', ip='192.168.34.10/24')


    # Create switches
    s1 = net.addSwitch('s1', listenPort=6634, mac='00:00:00:00:00:01')
    s2 = net.addSwitch('s2', listenPort=6634, mac='00:00:00:00:00:02')
    s3 = net.addSwitch('s3', listenPort=6634, mac='00:00:00:00:00:03')

    # create links
    print "*** Creating links"
    net.addLink(h1, s1, )
    net.addLink(s1, s2, )
    net.addLink(s2, s3, )
    net.addLink(h2, s3, )

    # Create controller access
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6533)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6633)

    net.build()
    s1.start([c0])
    s2.start([c1])
    s3.start([c1])

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


if __name__ == '__main__':
    Main()
