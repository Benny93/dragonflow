#!/usr/bin/python
"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""
import time
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.node import RemoteController

def Main():
    setLogLevel('info')
    net = Mininet(topo=None, build=False)

    # Create nodes
    h1 = net.addHost('h1', mac='01:00:00:00:01:00', ip='192.168.0.1/24')
    h2 = net.addHost('h2', mac='01:00:00:00:02:00', ip='192.168.0.2/24')

    # Create switches
    s1 = net.addSwitch('s1', listenPort=6634, mac='00:00:00:00:00:01')
    s2 = net.addSwitch('s2', listenPort=6634, mac='00:00:00:00:00:02')

    # create links
    print "*** Creating links"
    net.addLink(h1, s1, )
    net.addLink(h2, s2, )
    net.addLink(s1, s2, )

    # Create controller access
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6533)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6633)

    net.build()
    s1.start([c0])
    s2.start([c1])

    s1.cmdPrint('ovs-vsctl show')

    print "Ping h2 from h1"
    try:
        while True:
            print h1.cmd('ping -c1 %s' % h2.IP())
            time.sleep(1)
    except KeyboardInterrupt:
        print "\nWarning: Caught KeyboardInterrupt, stopping network"
        net.stop()


if __name__ == '__main__':
    Main()
