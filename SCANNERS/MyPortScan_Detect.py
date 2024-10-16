#!/usr/bin/env python
 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import TCP, IP
from impacket import ImpactDecoder, ImpactPacket
import time

THRESHOLD = 50
WINDOW = 5
PORTS=[]

    
        

def portscan_detect(pkt):
    # Get the source IP address
    src_ip = pkt[IP].src
    port_count = {}
    scanners = {}
    cur_time = time.time()
 
    # Get the source port number
    tcp_header = packet.getlayer(TCP)
    src_port = tcp_header.sport
    dis_port = tcp_header.dport
 
        # Check if this is a new connection
    if (src_ip, src_port) not in last_packet_time:
        last_packet_time[(src_ip, src_port)] = time.time()
        port_count[(src_ip, src_port)] = 1
     
    # Check if this is a connection to a new port
    last_packet_time = last_packet_time[(src_ip, src_port)]
    if time.time() - last_packet_time > WINDOW:
        port_count[(src_ip, src_port)] = 0
        last_packet_time[(src_ip, src_port)] = time.time()
        port_count[(src_ip, src_port)] += 1
        counts = port_count[(src_ip, src_port)] 
        PORTS.append(dis_port)
        # Check if we have reached the threshold for this connection
    dates=scanners(src_ip) 
    if counts >= THRESHOLD:
        scanners.append(src_ip)
        print(f"Scanner detected. The scanner originated from host {src_ip}.")
        AllPorts = '\n'.join(map(str,PORTS))
        print("Ports Scanned [",AllPorts,"]")
        quit()
 
def main():
    sniff(prn=portscan_detect, filter="tcp", store=0)
 
if __name__ == "__main__":
    main()