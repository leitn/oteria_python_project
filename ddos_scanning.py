from scapy.all import *
from scapy.layers.inet import ICMP #Can be removed, it just allows VSCode to not flag an error on "ICMP" keyword being used in maDefinition()
import time


too_many_pkts = False
ping_int = 0
start_time = time.time()

def	f_stopfilter(pkt):
	if too_many_pkts == True:
		print("[TOO MANY PINGS RECEIVED THIS IS WEIRD]\n") #à changer quand on aura un système d'alerte
		return (True)
	else:
		return (False)

def	maDefinition(pkt):
	''' Every 5 seconds, checks that our machine doesn't receive more than 100 PINGS every 5 seconds'''
	global too_many_pkts
	global ping_int
	global start_time

	curr_time = time.time()
	if(curr_time - start_time > 5): #garantie un reset de l'incrémentation toutes les 5 secondes
		ping_int = 0 #reset du compteur
		start_time = time.time() #reset du temps de référence
	if ICMP in pkt: 
		ping_int = ping_int + 1
		print(f'"Received PING n°{ping_int}\n"')
		if(pkt.getlayer(Raw)): 
			readable = bytes(pkt.getlayer(Raw)).decode('UTF-8', 'replace') #pour le plaisir de print les messages reçus mais inutiles
			print(readable)
	if (ping_int > 100):
		too_many_pkts = True
	return (1)

def main():
	while True:
		print("Waiting for a PING....\n")
		sniff(prn=maDefinition, filter="icmp", stop_filter=f_stopfilter)
		break

if __name__ == "__main__":
    main()