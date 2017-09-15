"""
Parse and Plot Ping results
"""
import csv
import matplotlib.pyplot as plt
import sys

mydict = []
file_name = fn = sys.argv[1]
with open(file_name, 'rb') as csvf:
    reader = csv.DictReader(csvf, delimiter=',')
    for row in reader:
        mydict.append(row)
time_list = []
ping_list = []
for d in mydict:
    time_list.append(d['time'])
    ping_list.append(d['maxping'])

plt.plot(time_list, ping_list)


