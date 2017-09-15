#!/usr/bin/env python
"""
Starts RYU controller from code.
Used for debugging
"""

import sys
from ryu.cmd import manager

# sys.argv.append('ws_topology.py')
sys.argv.append('simple_switch_13.py')
sys.argv.append('--verbose')
sys.argv.append('--observe-links')
# ipv6 listen host
#sys.argv.append('--ofp-listen-host')
#sys.argv.append('::')
sys.argv.append('--enable-debugger')
manager.main()
