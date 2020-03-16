#!/usr/bin/env python3.6

from scapy.all import *
import struct
import string
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="interface to scan on")
parser.add_argument("timeout", help="time to scan")
args = parser.parse_args()

# Liste de tous les APs qui n'annoncent pas leur SSID (cachés)
hidden_list = []
# Liste de tous les SSID cachés qu'on découvre dans les probe responses
hidden_name = []

# On snif et isole les Beacons frame avec un SSID à 0 (cachés)
def snifSSID(trame):
    global ap_list
    if trame.haslayer(Dot11Beacon):
        if trame.addr2 not in hidden_list:
            # Soit le nom est vide, soit il contient uniquement des bytes à 0
            if(trame.info == '') or (not(all(chr(c) in string.printable for c in trame.info))):
                hidden_list.append(trame.addr2)

# On snif les noms des APs qui on été précédement mis dans la liste hidden_list
def snifName(trame):
    # Si c'est une proe response dans la liste on ajoute le nom et on l'affiche
    if trame.haslayer(Dot11ProbeResp):
        if trame.addr2 in hidden_list:
            if trame.info not in hidden_name:
                hidden_name.append(trame.info)
                print("AP caché trouvé: ",trame.info.decode('utf-8'))

# Première étape, scan de args.timeout seconde afin de récupéré les SSID pertinent
print("Scan des SSID cachés en cours")
sniff(iface=args.interface, prn=snifSSID, timeout=int(args.timeout))
if hidden_list == []:
    print("Aucun AP caché n'a été trouvé pendant le scan initial. Veuillez réessayer")
    sys.exit()
print("Attente d'une connexion aux AP cachés :")
# Deuxieme étape, scan infini qui affiche le nom du réseau caché quand quelqu'un s'y connecte
sniff(iface=args.interface, prn=snifName)



