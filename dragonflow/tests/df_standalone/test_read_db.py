#!/usr/bin/python
import sys
from dragonflow.cli import df_db


def main():
    sys.argv.append('tables')
    df_db.main()
    sys.argv.pop()
    sys.argv.append('ls')
    sys.argv.append('lswitch')
    df_db.main()
    sys.argv.pop()
    sys.argv.append('lport')
    df_db.main()
    sys.argv.pop()
    sys.argv.append('migration')
    df_db.main()
    sys.argv.pop()
    sys.argv.append('portstats')
    df_db.main()


if __name__ == "__main__":
    sys.exit(main())