#!/usr/env/python

import os
import sys
import paramiko
import time

# ssl settings
hostkeytype = None
hostkey = None
# Router
ROUTER_IP_IF = '2017:db8::f2ff'
# Controller
LOAD_FILE_PATH = '/home/ubuntu/sf_SDN/dragonflow/dragonflow/tests/df_standalone'
LOAD_FILE_PREFIX = 'load_at_'
LOAD_FILE_SUFFIX = '.txt'
CONTROLLER1_HOST_NAME = 'controller1'
CONTROLLER2_HOST_NAME = 'controller2'
CONTROLLER1_IP = "192.168.33.101"
CONTROLLER2_IP = "192.168.33.102"
# orchestrator settings
POLLING_INTERVAL = 1


def create_session(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    client.connect(ip, username=username, password=password)
    return client


def poll_ctl_load(session, hostname):
    cmd = 'cat {}/{}{}{}'.format(LOAD_FILE_PATH, LOAD_FILE_PREFIX, hostname,
                                 LOAD_FILE_SUFFIX)
    print "{} load:".format(hostname)
    load = 0
    stdin, stdout, stderr = session.exec_command(cmd)
    for line in stdout:
        print line.strip('\n')
        # assert line is loadvalue
        load =int(line)
    for line in stderr:
        print line.strip('\n')

    return load

def set_router_weights(ctls, session):
    ctl1_weight = ctls[CONTROLLER1_HOST_NAME]["weight"]
    ctl2_weight = ctls[CONTROLLER2_HOST_NAME]["weight"]
    cmd_adjust_weight = "sudo ip -6 route replace 2017:db8::ffaa " \
                        "nexthop via 2017:db8::f201 dev enp0s9 weight {} " \
                        "nexthop via 2017:db8::f301 dev enp0s10 weight {}".format(ctl1_weight, ctl2_weight)
    print "Deploying command on router: {}".format(ROUTER_IP_IF)
    print cmd_adjust_weight
    _, stdout, stderr = session.exec_command(cmd_adjust_weight)
    for line in stdout:
        print line.strip('\n')
    for line in stderr:
        print line.strip('\n')


ctl1_session = create_session(CONTROLLER1_IP, "ubuntu", "ubuntu")
ctl2_session = create_session(CONTROLLER2_IP, "ubuntu", "ubuntu")
router_session = create_session(ROUTER_IP_IF, "ubuntu", "ubuntu")

if (ctl1_session or ctl2_session) and router_session:
    ctls = {}
    # Hostname should be unique...
    ctls[CONTROLLER1_HOST_NAME] = {"ssh": ctl1_session, "load": 0, "weight": 1}
    ctls[CONTROLLER2_HOST_NAME] = {"ssh": ctl2_session, "load": 0, "weight": 1}

    try:
        while True:
            load_sum = 0
            for key in ctls.keys():
                ctl_load = poll_ctl_load(session=ctls[key]["ssh"], hostname=key)
                ctls[key]["load"] = ctl_load
                load_sum += ctl_load
            for key in ctls.keys():
                weight = 1
                if load_sum == 0:
                    weight = 1 / len(ctls)
                else:
                    weight = 1 - (float(ctls[key]["load"])/ load_sum)
                ctls[key]["weight"] = int(min(max(100 * weight, 1), 99))

            # update weights of router
            set_router_weights(ctls=ctls, session=router_session)
            time.sleep(POLLING_INTERVAL)
    except KeyboardInterrupt:
        print "KeyboardInterrupt received.\n Closing ssh connections...\n"
        ctl1_session.close()
        ctl2_session.close()
        router_session.close()
else:
    print "Could not connect to any controller or router!\n"
