from scapy.all import *
from scapy.layers.inet import IP, TCP #Can be removed, it just allows VSCode to not flag an error on thos keywords
import time
from discord_alert import *

# Dictionnaire pour stocker le nombre de tentatives de connexion par IP source
cpt_test = {}

# Fonction pour analyser chaque paquet
def detect_brute_force(pkt):
    # Vérifie si le paquet est du TCP, qu'il est destiné au port 22 et que le flag SYN est activé
    if pkt.haslayer(TCP) and pkt[TCP].dport == 22 and pkt[TCP].flags == "S":
        src_ip = pkt[IP].src
        cur_time = time.time()

        # Si c'est la première tentative de cette IP, on l'initialise
        if src_ip not in cpt_test:
            cpt_test[src_ip] = [cur_time]
        else:
            # Ajoute la nouvelle tentative pour cette IP
            cpt_test[src_ip].append(cur_time)

            # On garde seulement les tentatives dans la dernière minute (30 secondes)
            cpt_test[src_ip] = [t for t in cpt_test[src_ip] if cur_time - t <= 30]

            # Si il y a 3 ou plus tentatives en 30 secondes (correspondant à 5 tests SSH)
            if len(cpt_test[src_ip]) == 6:
                msg = f"[ALERTE] Potentielle attaque par force brute détectée de {src_ip} sur le port 22 !"
                print(msg)
                fill_log(msg, pkt)
                send_discord_alert(msg, 2)

# Capture des paquets sur l'interface réseau
sniff(filter="tcp port 22", prn=detect_brute_force, iface="VMnet8")