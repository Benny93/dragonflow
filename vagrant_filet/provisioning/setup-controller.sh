#!/usr/bin/env bash
# Get the IP address
#ipaddress=$(/sbin/ifconfig eth1 | grep 'inet addr' | awk -F' ' '{print $2}' | awk -F':' '{print $2}')
# requres root

#enable ip forwarding
#echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
# install dependencys
#cd home/vagrant/dragonflow
#encoding
#python /home/vagrant/fix_encoding.py
#pip install --user -r requirements.txt
echo "CONTROLLER SETUP DONE"
