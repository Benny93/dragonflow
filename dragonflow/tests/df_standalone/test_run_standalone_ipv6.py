#!/usr/env/python

import sys

# FIX for starting this module
try:
    import dragonflow
except:
    sys.path.append('/home/ubuntu/sf_SDN/dragonflow');
    sys.path.append('/media/sf_SDN/dragonflow/dragonflow/tests/df_standalone');
    print "DF was not found, upadeted Path to: {}".format(sys.path)

from dragonflow import conf as cfg
from ryu.cmd import manager
from dragonflow.neutron.common import config as common_config
from load_monitoring import override_load_file


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
    # try:
    #     port = str(input("Specify controller port. Empty is default\nController listens to Port:"))
    # except Exception:
    #     port = ""

    # sys.argv.append('--config-file')
    # sys.argv.append('/home/vagrant/dragonflow/etc/neutron.conf')
    sys.argv.append('--config-file')
    sys.argv.append('../../../etc/dragonflow.ini')
    # sys.argv.append('ws_topology.py')
    sys.argv.append('l2_app_concept2.py')
    sys.argv.append('l3_app_concept2.py')
    # sys.argv.append('/home/vagrant/dragonflow/dragonflow/controller/ryu_base_app.py')
    # sys.argv.append('/home/vagrant/dragonflow/dragonflow/controller/apps/l2.py')
    sys.argv.append('--verbose')
    sys.argv.append('--observe-links')

    common_config.init(sys.argv[1:3])
    common_config.setup_logging()

    # if port is not "":
    #     print "Setting Port {}".format(port)
    #     sys.argv.append('--ofp-tcp-listen-port')
    #     sys.argv.append(port)

    # ipv6 listen host
    sys.argv.append('--ofp-listen-host')
    sys.argv.append('::')
    # sys.argv.append('--enable-debugger')

    # set controller load to 0
    override_load_file(0)

    try:
        manager.main()
    except KeyboardInterrupt:
        override_load_file(0)
        print "Exiting because keyboard interrupt was received."


if __name__ == "__main__":
    sys.exit(main())
