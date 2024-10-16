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
	'''Interrompt le sniff() dès qu'un scanning
        de port est détecté'''
	msg = "Alerte : scanning de ports en court\n"
	print(msg)
	fill_log(msg, pkt) 
	send_discord_alert(msg, 3) 
	return (True)

    
def portscan_detect(pkt):
    '''
        Surveille les paquets reçus avec sniff()
        et envoie une alerte en cas de suspicion de scan
        de ports en court.

        Incrémente SCAN_COUNT et le reset à zéro toutes 
        les WINDOW secondes. Si SCAN_COUNT dépasse un 
        nombre définit dans THRESHOLD, met le booléen 
        SCAN_BOOL à True, ce qui déclenche
        f_stopfilter, qui envoie une alerte à un serveur
        discord et note l'évènement dans un document
        text de log. 
        
        '''
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
    # Repère les synchronisations (SYN, flag 'S') du protocole TCP, indiquant que les paquets
    # reçus vérifient que nos ports sont ouverts ou non.
    if TCP in pkt and pkt[TCP].flags == 'S': 
        SCAN_COUNT = SCAN_COUNT + 1
        print(f'Received PING n°{SCAN_COUNT}\n')
    if (SCAN_COUNT > THRESHOLD): 
        SCAN_BOOL = True
 
def main():
    sniff(prn=portscan_detect, filter="tcp", stop_filter=f_stopfilter)
 
if __name__ == "__main__":
    main()