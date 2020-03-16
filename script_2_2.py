#!/usr/bin/env python3.6

"""
Ce script permet de match les différentes stations qui communiquent avec une liste d'AP.

Remarque : Toutes stations communicant avec une AP dans la liste prealablement remplie via un sniffing de beacon et ne faisant pas partie
            de la liste des APs est considéré comme une station. Il y a risque que parmis les stations, des APs s'y cachent.

Syntax d'utilisation : sudo python script_2_2.py interface timeoutAP timeoutMatch

Auteurs : Polier Florian, Tran Eric
Date : 16.03.2020
"""

from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Interface monitoring")
parser.add_argument("timeoutAP", help="Timeout for the APs sniffing (Secondes)")
parser.add_argument("timeoutMatch", help="Timeout for the ap <-> sta match (Secondes)")
args = parser.parse_args()


global APDic #Contient la liste des APs ainsi que les stations qui sont associes avec.
APDic = {}

global broadcastMAC
broadcastMAC = "ff:ff:ff:ff:ff:ff"

# Cette fonction permet de tester des mac adresses selon s'il s'agit d'une AP, broadcast ou station et de faire les bonnes operations en consequences.
def testAPAddress(ap, mac1, mac2):
    if ap in APDic:
        if not mac1 in APDic and not mac1 == broadcastMAC:
            APDic[ap].add(mac1)
        if not mac2 in APDic and not mac2 == broadcastMAC:
            APDic[ap].add(mac2)

# Remplit la liste (Dictionnaire) des APs via un sniffing des beacons.
def sniffAPHandler(trame):
    if trame.haslayer(Dot11Beacon):
        if trame.haslayer(Dot11Elt):
            decodeInfo = trame.info.decode("utf-8")
            if not trame.addr3 in APDic:
               APDic[trame.addr3] = set()


# Permet de relier les associations entre les APs et les stations presentes.
def sniffCommAPandSTA(trame):
    if (trame.haslayer(Dot11) and trame.type == 2) or trame.haslayer(Dot11QoS) :
        testAPAddress(trame.addr1, trame.addr2, trame.addr3)
        testAPAddress(trame.addr2, trame.addr1, trame.addr3)
        testAPAddress(trame.addr3, trame.addr1, trame.addr2)


sniff(iface=args.interface, prn=sniffAPHandler, timeout=int(args.timeoutAP)) #timeout en secondes

sniff(iface=args.interface, prn=sniffCommAPandSTA, timeout=int(args.timeoutMatch)) 

# Affichage
print("APs                                       STAs")
for key in APDic :
    if len(APDic[key]) > 0:
        result = key + "                         "
        for val in APDic[key]:
            result += val + ", " 
        print(result)








