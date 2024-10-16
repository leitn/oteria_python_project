
from scapy.all import *
from scapy.layers.inet import ICMP, IP #Can be removed, it just allows VSCode to not flag an error on those keywords
import time
from discord_alert import *
from my_logging import *
	
THRESHOLD = 50
WINDOW = 5
DDOS_BOOL = False
PING_COUNT = 0
COMPARE_TIME = time.time()


def	f_stopfilter(pkt):
	'''Interrompt le sniff dès qu'une attaque 
		est détectée'''
	msg = "Alerte : risque potentiel de DDOS\n"
	print(msg)
	fill_log(msg, pkt) 
	send_discord_alert(msg, 1) 
	return (True)

def	ddos_detect(pkt):
	''' Vérifie toutes les WINDOW secondes que sniff 
		n'ai pas repéré plus de THRESHOLD PINGS dans les 
		5 dernières secondes.'''
	
	global DDOS_BOOL
	global PING_COUNT
	global COMPARE_TIME
	global THRESHOLD
	global WINDOW

	curr_time = time.time()
	if(curr_time - COMPARE_TIME >= WINDOW): #reset le compteur toutes les WINDOW secondes et reset le COMPARE_TIME de référence
		PING_COUNT = 0 
		COMPARE_TIME = time.time() 
	if ICMP in pkt: 
		PING_COUNT = PING_COUNT + 1
		print(f'Received PING n°{PING_COUNT}\n')
	if (PING_COUNT > THRESHOLD): #on ne peut rentrer dans cette condition que si le PING_COUNT s'est incrémenté en <= 5 secondes
		DDOS_BOOL = True #triggers f_stopfilter

def main():
	print("Waiting for a PING....\n")
	sniff(prn=ddos_detect, filter="icmp", stop_filter=f_stopfilter)
	
if __name__ == "__main__":
    main()