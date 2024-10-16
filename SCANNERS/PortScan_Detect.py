#!/usr/bin/env python
from scapy.all import *
from scapy.layers.inet import TCP, IP
import time
from discord_alert import *
from my_logging import *
	

THRESHOLD = 50
WINDOW = 5
SCAN_BOOL = False
COMPARE_TIME = time.time()
SCAN_COUNT = 0


def	f_stopfilter(pkt):
	'''Interrompt le sniff dès qu'un scanning
        de port est détecté'''
	msg = "Alerte : scanning de ports en court\n"
	print(msg)
	fill_log(msg, pkt) 
	send_discord_alert(msg, 3) 
	return (True)

    
def portscan_detect(pkt):
    global SCAN_BOOL
    global SCAN_COUNT
    global COMPARE_TIME
    global THRESHOLD
    global WINDOW
	
    curr_time = time.time()
	#reset le compteur toutes les WINDOW secondes et reset le COMPARE_TIME de référence
    if(curr_time - COMPARE_TIME >= WINDOW): 
        SCAN_COUNT = 0 
        COMPARE_TIME = time.time() 
    if TCP in pkt and pkt[TCP].flags == 'S': 
        SCAN_COUNT = SCAN_COUNT + 1
        print(f'Received PING n°{SCAN_COUNT}\n')
    if (SCAN_COUNT > THRESHOLD): 
        SCAN_BOOL = True
 
def main():
    sniff(prn=portscan_detect, filter="tcp", stop_filter=f_stopfilter)
 
if __name__ == "__main__":
    main()