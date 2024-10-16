
from scapy.all import *
from scapy.layers.inet import ICMP, IP #Can be removed, it just allows VSCode to not flag an error on "ICMP" keyword being used in maDefinition()
import requests
import time
from discord_alert import *

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
	
THRESHOLD = 50
WINDOW = 5
DDOS_BOOL = False
PING_COUNT = 0
START_TIME = time.time()
COMPARE_TIME = time.time()


def fill_log(str, pkt):
	f = os.path.join(__location__, 'logs/DDOS_Detect_Logfile.txt')
	if IP in pkt:
		pkt_addr = pkt[IP].src
	if DDOS_BOOL == False:
		with open(f, 'a') as file:
			file.write(f"[FROM : {pkt_addr} : {str}")
			curr_time = time.time()
			if (curr_time - START_TIME >= 86400): #Après 24h sans DDOS détécté, on efface les logs.
				file.truncate(0)
	else:
		with open(f, 'a') as file:
			file.write(str)
			file.close() #On arrête d'écrire dans les logs en cas de DDOS car ça peut spammer inutilement.

def decode_raw(pkt):
	if(pkt.getlayer(Raw)): 
		load = pkt.getlayer(Raw)
		readable = bytes(load.decode('UTF-8', 'replace'))
		print(readable)


def	f_stopfilter(pkt):
	'''Interrompt le sniff dès qu'une attaque 
		est détectée'''
	msg = "Alerte : risque potentiel de DDOS\n"
	if DDOS_BOOL == True:
		print(msg)
		fill_log(msg) 
		send_discord_alert(msg, 1) 
		return (True)
	else:
		return (False)

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
		decode_raw(pkt)
		fill_log(f'Received PING n°{PING_COUNT}\n', pkt)
	if (PING_COUNT > THRESHOLD): #on ne peut rentrer dans cette condition que si le PING_COUNT s'est incrémenté en <= 5 secondes
		DDOS_BOOL = True #triggers f_stopfilter
	return (1)

def main():
	while True:
		print("Waiting for a PING....\n")
		sniff(prn=ddos_detect, filter="icmp", stop_filter=f_stopfilter)
		break

if __name__ == "__main__":
    main()