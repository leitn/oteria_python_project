from scapy.all import *
import time

def maDefinition(pkt):
    print("Sniffing...")
    time.sleep(3)
    pkt.show()

sniff(iface='wlo1', prn=maDefinition)