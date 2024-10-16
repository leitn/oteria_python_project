from scapy.all import *
from scapy.layers.inet import TCP, IP
import time

# Dictionnaire pour stocker le nombre de tentatives de connexion par IP source
conn_attempts = {}

# Fonction pour analyser chaque paquet
def detect_brute_force(pkt):
    # Vérifie si le paquet est du TCP et qu'il est destiné au port 22
    if pkt.haslayer(TCP) and pkt[TCP].dport == 22:
        src_ip = pkt[IP].src
        current_time = time.time()

        # Si c'est la première tentative de cette IP, on l'initialise
        if src_ip not in conn_attempts:
            conn_attempts[src_ip] = [current_time]
            print("connexion received for first time")
        else:
            # Ajoute la nouvelle tentative pour cette IP
            conn_attempts[src_ip].append(current_time)
            temp_attempts = {}

            # On garde seulement les tentatives dans la dernière minute (60 secondes)
            temp_attempts[src_ip] = [t for t in conn_attempts[src_ip] if current_time - t <= 60]
            print(temp_attempts)

            # Si exactement 5 tentatives en 60 secondes, alerte
            if len(temp_attempts[src_ip]) >= 5:
                print(f"[ALERTE] Potentielle attaque par force brute détectée de {src_ip} sur le port 22 !")

# Capture des paquets sur l'interface réseau (adapter 'eth0' selon ta configuration)
sniff(filter="tcp port 22", prn=detect_brute_force, iface="wlo1")