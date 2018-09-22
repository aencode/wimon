#!/usr/bin/python3

import sys
import os
import time

if(len(sys.argv) > 1):
	iface=sys.argv[1]
else:
	print("please give interface name")
	exit(0)
ch=0

def channel_hop():
	while 1:
		for ch in range(1,15):
			time.sleep(0.5)
			os.system("iwconfig "+iface+" channel "+str(ch))

channel_hop()
