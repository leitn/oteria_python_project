from scapy.all import *
from collections import defaultdict
import threading
from six import *
import time

# Dictionnaire pour compter les requêtes ICMP Echo Request (ping) par IP source
compteur_icmp = defaultdict(int)

# Intervalle de temps (en secondes) pour analyser les paquets
intervalle_temps = 4  # Vérifie toutes les 10 secondes
seuil_ping_flood = 10  # Seuil d'alerte pour un ping flood (nombre de requêtes)

# Détection Ping Flood
def detecter_ping_flood(paquet):
    print("DANS DETECTER_PING_FLOOD\n")
    # Vérifie si le paquet est un paquet ICMP Echo Request (type 8)
    if paquet.haslayer(ICMP) and paquet[ICMP].type == 8:  # 8 correspond à Echo Request haslayer vérifie que la couche est présente
        source_ip = paquet[IP].src
        cible_ip = paquet[IP].dst

        # Incrémente le nombre de pings venant de cette IP source
        compteur_icmp[source_ip] += 1

        print(f"Requête ICMP Echo (ping) reçue de {source_ip} vers {cible_ip}")

# Fonction pour analyser les paquets toutes les x secondes
def analyser_paquets():
    while True:
        print("\nAnalyse en cours...")
        time.sleep(intervalle_temps)

        # Vérifie le compteur de chaque IP
        for ip, nombre_paquets in compteur_icmp.items():
            if nombre_paquets > seuil_ping_flood:
                print(f"!!! Alerte Ping Flood !!! Trop de pings de {ip} ({nombre_paquets} paquets)")
            else:
                print("BBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH\n")

        # Réinitialise le compteur pour la prochaine période
        compteur_icmp.clear()

# Fonction principale pour sniffer les paquets ICMP et lancer l'analyse
def lancer_detection_ping_flood():
    print("Détection Ping Flood en cours...")
    # Sniffe les paquets ICMP (Echo Request de type 8)
    sniff(prn=detecter_ping_flood, filter="ICMP")

# Démarrer la détection et l'analyse dans un thread séparé
analyser_paquets
lancer_detection_ping_flood

