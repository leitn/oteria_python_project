
from scapy.all import *
from scapy.layers.inet import ICMP, TCP, IP #Can be removed, it just allows VSCode to not flag an error on those keywords
import time
from discord_alert import *
from my_logging import *
	
THRESHOLD = 50 #nombre de connexions maximales avant de sonner l'alarme
WINDOW = 5 #le temps dans lequel ces connexio # Si il y a 3 ou plus tentatives en 30 secondes (correspondant à 5 tests SSH)ns doivent avoir lieu, en secondes
DDOS_BOOL = False #Flag annonçant une attaque DDOS
SCAN_BOOL = False #Flag annonçant un Scan de ports
BRUTE_BOOL = False
SCAN_COUNT = 0 #Compteur pour repérer un Scan de ports
PING_COUNT = 0 # Compteut pour repérer un DDOS
COMPARE_TIME = time.time() #temps initial d'entrée dans le NIDS, qui sere réutilisé toutes les WINDOW secondes

# Dictionnaire pour stocker le nombre de tentatives de connexion par IP source
cpt_test = {}

def f_alarm(msg, chan_flag, pkt):
	'''Fonction appelée par f_stopfilter
        Selon les attaques en cours, print un message d'erreur, remplit le logfile, et envoie une alrte discord'''
	msg = "Alerte : scanning de ports en court\n"
	print(msg)
	fill_log(msg, pkt) 
	send_discord_alert(msg, chan_flag)
	return(True)
	

def	f_stopfilter(pkt):
	'''Fonction qui interrompt le sniff
       Print sur la sortie standard un message d'informations
	   Remplit le log avec les informations de l'attaque en court (Heure, IP...)
	   Envoie une alerte discord'''
	if DDOS_BOOL == True or SCAN_BOOL == True or BRUTE_BOOL:
		if DDOS_BOOL == True and SCAN_BOOL == False:
			f_alarm("Alerte : risque potentiel de DDOS\n", 1, pkt)
		elif SCAN_BOOL == True and DDOS_BOOL == False:
			f_alarm("Alerte : scanning de ports en court\n", 3, pkt)
		return (True)
	else:
	    return (False)
	
def detect_brute_force(pkt):
	'''Fonction pour analyser chaque paquet'''
	global BRUTE_BOOL
	if pkt.haslayer(TCP) and pkt[TCP].dport == 22 and pkt[TCP].flags == "S":# Vérifie si le paquet est du TCP, qu'il est destiné au port 22 et que le flag SYN est activé
		src_ip = pkt[IP].src
		cur_time = time.time()
		if src_ip not in cpt_test: # Si c'est la première tentative de cette IP, on l'initialise
			cpt_test[src_ip] = [cur_time]
		else:
			cpt_test[src_ip].append(cur_time)  # Ajoute la nouvelle tentative pour cette IP
			cpt_test[src_ip] = [t for t in cpt_test[src_ip] if cur_time - t <= 30] # On garde seulement les tentatives dans la dernière minute (30 secondes)
			if len(cpt_test[src_ip]) == 6:  # Si il y a 3 ou plus tentatives en 30 secondes (correspondant à 5 tests SSH)
				msg = f"[ALERTE] Potentielle attaque par force brute détectée de {src_ip} sur le port 22 !"
				print(msg)
				fill_log(msg, pkt)
				send_discord_alert(msg, 2)
				BRUTE_BOOL = True

def	ddos_detect(pkt):
	'''
        Surveille les paquets reçus avec sniff()
        et envoie une alerte en cas de suspicion de ddos en court.

        Incrémente PING_COUNT et le reset à zéro toutes 
        les WINDOW secondes. Si SCAN_COUNT dépasse un 
        nombre définit dans THRESHOLD, met le booléen 
        PING_BOOL à True, ce qui déclenche
        f_stopfilter, qui envoie une alerte à un serveur
        discord et note l'évènement dans un document
        text de log. 
        
        '''
	
	global DDOS_BOOL
	global PING_COUNT
	global COMPARE_TIME
	global THRESHOLD
	global WINDOW

	curr_time = time.time()
	if(curr_time - COMPARE_TIME >= WINDOW): #reset le compteur toutes les WINDOW secondes et reset le COMPARE_TIME de référence
		PING_COUNT = 0 
		COMPARE_TIME = time.time() 
	else: 
		PING_COUNT = PING_COUNT + 1
		print(f'Received PING n°{PING_COUNT}\n')
	if (PING_COUNT > THRESHOLD): #on ne peut rentrer dans cette condition que si le PING_COUNT s'est incrémenté en <= 5 secondes
		DDOS_BOOL = True #triggers f_stopfilter
		
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
        print(f'Received SCAN n°{SCAN_COUNT}\n')
    if (SCAN_COUNT > THRESHOLD): 
        SCAN_BOOL = True
		

def f_nids(pkt):
	'''Envoie le paquet aux fonctions pertinentes du NIDS.
	    Si le protocole ICMP est présent, on vérifie qu'il n'y a pas un DDOS en cours
		Sinon, on vérifie qu'il n'y ait ni de bruteforce ni de scanner de ports en cours'''
	if ICMP in pkt:
		ddos_detect(pkt)
	elif TCP in pkt:
		detect_brute_force(pkt)
		portscan_detect(pkt)
		

def main():
	print("Waiting for a PING....\n")
	sniff(prn=f_nids, filter="icmp or tcp or tcp port 22", stop_filter=f_stopfilter)
	
if __name__ == "__main__":
    main()