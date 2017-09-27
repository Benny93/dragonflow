#!/usr/env/python
import sys
from ryu.cmd import manager

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
# ipv6 listen host
# sys.argv.append('--ofp-listen-host')
# sys.argv.append('::')
# sys.argv.append('--enable-debugger')
manager.main()
