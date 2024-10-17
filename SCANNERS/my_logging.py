from scapy.all import *
import time
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__))) #Obtient le path dans lequel le fichier se situe

def fill_log(str, pkt):
	'''Ouvre un fichier à un path f
	   et y écrit un message de log
		avant de le fermer'''
	f = os.path.join(__location__, 'log.txt') #créer le lien du fichier log pour le créer à cette addresse
	if IP in pkt:
		pkt_addr = pkt[IP].src #récupère l'adresse IP
	with open(f, 'a') as file: #ouvre en mode "append"
		n = time.time()
		time_format = time.strftime("%D:%H:%M:%S", time.gmtime(n)) #calcule l'heure et la date à l'instant t
		file.write(f"[{time_format}] [IP : {pkt_addr} ]: {str}") #écrit date et horaire, IP, et message
	file.close()
	return 0