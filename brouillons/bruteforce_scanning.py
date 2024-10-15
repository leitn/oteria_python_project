import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from impacket import ImpactDecoder, ImpactPacket
import time

# Define the number of consecutive ports to trigger detection
THRESHOLD = 15
# Define the time window in which ports are being scanned
WINDOW = 5

def handle_packet(self, packet):
   # Get the source IP address
   ip_header = packet.getlayer(IP)
   src_ip = ip_header.src
 
   # Get the source port number
   tcp_header = packet.getlayer(TCP)
   src_port = tcp_header.sport
   dis_port = tcp_header.dport
 
   # Check if this is a new connection
   if (src_ip, src_port) not in self.last_packet_time:
       self.last_packet_time[(src_ip, src_port)] = time.time()
       self.port_count[(src_ip, src_port)] = 1
       return
 
   # Check if this is a connection to a new port
   last_packet_time = self.last_packet_time[(src_ip, src_port)]
   if time.time() - last_packet_time > WINDOW:
       self.port_count[(src_ip, src_port)] = 0
   self.last_packet_time[(src_ip, src_port)] = time.time()
   self.port_count[(src_ip, src_port)] += 1
   counts = self.port_count[(src_ip, src_port)] 
   PORTS.append(dis_port)
   # Check if we have reached the threshold for this connection
   dates=self.scanners.add(src_ip) 
   if counts >= THRESHOLD:
       self.scanners.add(src_ip)
       print(f"Scanner detected. The scanner originated from host {src_ip}.")
       AllPorts = ','.join(map(str,PORTS))
       print("Ports Scanned [",AllPorts,"]")
       quit()

handle_packet()