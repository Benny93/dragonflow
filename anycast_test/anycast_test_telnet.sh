#!/bin/bash
echo "telnet test"
for ((i=1; i<= $1; i++))
do
    telnet 2017:db8::ffaa 1234
    #    sleep 1# ohne sleep um schneller Verteilung bestimmen zu können
done
