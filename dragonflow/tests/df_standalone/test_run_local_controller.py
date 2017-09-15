#!/usr/bin/python
import sys

from dragonflow.controller.df_local_controller import main as df_main


def main():
    sys.argv.append('--config-file')
    sys.argv.append('/home/vagrant/dragonflow/etc/neutron.conf')
    sys.argv.append('--config-file')
    sys.argv.append('/home/vagrant/dragonflow/etc/dragonflow.ini')
    df_main()


if __name__ == "__main__":
    sys.exit(main())
