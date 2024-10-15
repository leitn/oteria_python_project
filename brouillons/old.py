

from scapy.all import *
import socket

#---------------------SCAN PORTS OUVERTS -----------------------------

def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f'Port {port} [OPEN]\n')
            open_ports.append(port)
        sock.close()
    return open_ports

ip_address = '193.186.4.124'
open_ports = scan_ports(ip_address, 1, 1005)
print(open_ports)

