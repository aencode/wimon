#!/usr/bin/python

import threading
import time
import os
from scapy.all import *

ssid_info={}

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


def pkt_handler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0  and pkt.subtype == 8 :

			try:
				power=round(10*(math.log10(pkt.notdecoded[10]*pow(10,-7))),1)
			except ValueError:
				power=ssid_info[pkt.addr2][1]
				
			if pkt.addr2 in ssid_info:
				ssid_info[pkt.addr2][1]=power
				ssid_info[pkt.addr2][2]=ssid_info[pkt.addr2][2]+1
			else:
				ssid_info[pkt.addr2]=[pkt.info,power,1]


def sniffer():
#ssid sniffer
	sniff(iface=iface,prn=pkt_handler)
	
def displayer():
#displayer
	while 1:

		time.sleep(2)
		os.system("clear")
		print("%30s %18s \t\t%s\t%s" % ("SSID","BSSID","Power","Beacons"))
		for bssid,iinfo in ssid_info.items():
			print("%30s %18s \t\t%s\t%s" % (iinfo[0].decode('utf-8'),bssid,iinfo[1],iinfo[2]))
		#print(ssid_info)
		
	
		
t1=threading.Thread(target=sniffer,args=())
t2=threading.Thread(target=displayer,args=())
t3=threading.Thread(target=channel_hop,args=())

t1.start()
t2.start()
t3.start()


