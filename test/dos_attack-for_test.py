import sys, random
import scapy
from scapy.all import *
from scapy.layers.inet import ICMP, IP


dst_ip="10.100.02.160"
n_ips = 10
threads = 2
n_msg = 150

ips = []

def get_random_ips(n):
	for i in range(0,int(n)):
		ip_gen = str(random.randint(0,255)) + "." +str(random.randint(0,255)) + "." +str(random.randint(0,255)) + "." +str(random.randint(0,255))
		ips.append(ip_gen)
   

def main():
    get_random_ips(n_ips)
    print(ips)

    load = "Bonjour :>\n"
    send((IP(dst=dst_ip)/ICMP()/load)*int(n_msg), iface="wlo1")
    

if __name__ == "__main__":
    main()