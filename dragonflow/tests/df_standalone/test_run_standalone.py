#!/usr/env/python
import sys
from ryu.cmd import manager

def main():
    # if len(sys.argv) > 1:
    #     value = sys.argv.pop()
    #     option = sys.argv.pop()
    #     if option == '-ctl-port':
    #         port = value
    #
    #         ryu_cfg.CONF.ofp_tcp_listen_port = port
    #     else:
    #         print "unkown option {}".format(option)
    #         exit(1)
    port = str(input("Specify controller port. Empty is default"))


    #sys.argv.append('--config-file')
    #sys.argv.append('/home/vagrant/dragonflow/etc/neutron.conf')
    sys.argv.append('--config-file')
    sys.argv.append('/home/vagrant/dragonflow/etc/dragonflow.ini')
    # sys.argv.append('ws_topology.py')
    sys.argv.append('l2_app_concept2.py')
    # sys.argv.append('/home/vagrant/dragonflow/dragonflow/controller/ryu_base_app.py')
    # sys.argv.append('/home/vagrant/dragonflow/dragonflow/controller/apps/l2.py')
    sys.argv.append('--verbose')
    sys.argv.append('--observe-links')
    if port is not "":
        print "Setting Port {}".format(port)
        sys.argv.append('--ofp-tcp-listen-port')
        sys.argv.append(port)

    # ipv6 listen host
    # sys.argv.append('--ofp-listen-host')
    # sys.argv.append('::')
    # sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == "__main__":
    sys.exit(main())
