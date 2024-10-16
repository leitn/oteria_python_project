from scapy.all import *
import time
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

def fill_log(str, pkt):
	f = os.path.join(__location__, 'logs/log.txt')
	if IP in pkt:
		pkt_addr = pkt[IP].src
	with open(f, 'a') as file:
		n = time.time()
		time_format = time.strftime("%H:%M:%S", time.gmtime(n))
		file.write(f"[time: {time_format}] [IP : {pkt_addr} ]: {str}")
	return 0