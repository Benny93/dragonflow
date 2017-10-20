#!/usr/env/python

import os
import sys
import paramiko
import time
from subprocess import check_output

# ssl settings
hostkeytype = None
hostkey = None
# Router
ROUTER_IP_IF = '2017:db8::f2ff'
# Controller
BOOT_TIME=7
CTL_EXE_PATH = '/home/ubuntu/sf_SDN/dragonflow/dragonflow/tests/df_standalone'
LOG_FILE_PATH = '/home/ubuntu/sf_SDN/dragonflow/dragonflow/tests/df_standalone'
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
        load = int(line)
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


def start_df_sa(ctl_session, hostname):
    """
    Starts DF-SA in Backfround.
    stdout und stderr is written to a logfile
    :param ctl_session:
    :param hostname:
    :return:
    """
    print "Starting {}".format(hostname)
    change_dir = 'cd {}'.format(CTL_EXE_PATH)
    start_ctl = 'python2 test_run_standalone_ipv6.py &> {}/log_{}.txt &'.format(LOG_FILE_PATH,hostname)
    pid_descr = ""
    _, stdout, stderr = ctl_session.exec_command('{};{}'.format(change_dir, start_ctl))



def stop_df_sa(ctl_session, hostname):
    print "Stopping {}".format(hostname)
    # keyboard_interrupt = 'kill -SIGINT {}'.format(pid)
    stop_all_python_processes = "kill -9  $(pgrep python2)"

    print "Sending: {} to {}".format(stop_all_python_processes, hostname)
    _, stdout, stderr = ctl_session.exec_command(stop_all_python_processes)
    # for line in stdout:
    #     print line.strip('\n')
    for line in stderr:
        print line.strip('\n')
    append_to_logfile = "echo \"{} stopped by orchestrator!\" >> {}/log_{}.txt".format(hostname, LOG_FILE_PATH,
                                                                                       hostname)
    _, stdout, stderr = ctl_session.exec_command(append_to_logfile)

# Creating sessions
ctl1_session = create_session(CONTROLLER1_IP, "ubuntu", "ubuntu")
ctl2_session = create_session(CONTROLLER2_IP, "ubuntu", "ubuntu")
router_session = create_session(ROUTER_IP_IF, "ubuntu", "ubuntu")

if (ctl1_session or ctl2_session) and router_session:
    ctls = {}
    # Hostname should be unique...
    ctls[CONTROLLER1_HOST_NAME] = {"ssh": ctl1_session, "load": 0, "weight": 1}
    ctls[CONTROLLER2_HOST_NAME] = {"ssh": ctl2_session, "load": 0, "weight": 1}

    start_df_sa(ctl_session=ctls[CONTROLLER1_HOST_NAME]["ssh"], hostname=CONTROLLER1_HOST_NAME)
    start_df_sa(ctl_session=ctls[CONTROLLER2_HOST_NAME]["ssh"], hostname=CONTROLLER2_HOST_NAME)

    print "Waiting {} seconds for controllers to boot".format(BOOT_TIME)
    time.sleep(BOOT_TIME)
    try:
        while True:
            # Clear terminal window first
            os.system('cls' if os.name == 'nt' else 'clear')
            print "ORCHESTRATOR:\n"
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
                    weight = 1 - (float(ctls[key]["load"]) / load_sum)
                ctls[key]["weight"] = int(min(max(100 * weight, 1), 99))

            # update weights of router
            set_router_weights(ctls=ctls, session=router_session)
            time.sleep(POLLING_INTERVAL)
    except KeyboardInterrupt:
        print "KeyboardInterrupt received.\n Closing ssh connections...\n"
        stop_df_sa(ctl1_session, CONTROLLER1_HOST_NAME)
        stop_df_sa(ctl2_session, CONTROLLER2_HOST_NAME)
        ctl1_session.close()
        ctl2_session.close()
        router_session.close()
else:
    print "Could not connect to any controller or router!\n"
