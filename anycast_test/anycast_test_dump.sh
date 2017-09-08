#!/bin/bash
IF='eth1'
ANYCAST='2017:db8::ffaa'
sudo tcpdump -ni $IF host $ANYCAST 
