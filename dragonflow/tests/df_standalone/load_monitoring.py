#!/usr/env/python
import socket

def override_load_file(load):
    hostname = socket.gethostname()
    # 'w' truncates existing files
    with open("load_at_{}.txt".format(hostname), 'w') as load_file:
        load_file.write(str(load))
        # end of with closes file automatically