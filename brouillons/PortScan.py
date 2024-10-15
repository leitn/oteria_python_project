from scapy.all import *
from scapy.layers.inet import TCP, IP
import socket

# Keep in mind :
    # - properly close connection (->FIN/ACK, <-FIN/ACK, ->ACK )

#---------------------SCAN PORTS OUVERTS -----------------------------

def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try: 
            pkt = IP(dst=(ip)) / TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f'Port {port} [OPEN] on {ip}\n')
                open_ports.append(port)
            else:
                print("Nope\n")
        except KeyboardInterrupt:
            print("Exiting Program\n")    
    
def main():
    target_ip = '10.100.10.190'
    scan_ports(target_ip, 1, 500)

if __name__ == "__main__":
    main()