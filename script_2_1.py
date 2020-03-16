#!/usr/bin/env python3.6

"""
Ce script permet lister les differentes stations cherchant des SSIDs specifiquent. (Via des probe request)

Syntax d'utilisation : sudo python script_2_1.py interface timeout

Auteurs : Polier Florian, Tran Eric
Date : 16.03.2020
"""


from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Interface monitoring")
parser.add_argument("timeout", help="Timeout for the sniffing (Secondes)")
args = parser.parse_args()

global staDic # Contient la liste des stations visant un SSID particulier
staDic = {}

def sniffProbeReqHandler(trame):
    if trame.haslayer(Dot11ProbeReq):
        decodeInfo = trame.info.decode("utf-8")
        if not decodeInfo == "" : #Empty String non voulu
            if decodeInfo in staDic:
                staDic[decodeInfo].add(trame.addr2)
            else:
                staDic[decodeInfo] = set([trame.addr2]) #[] dans le set permet d'initialiser avec une valeur sans qu'il le casse en plusieurs caracteres.

sniff(iface=args.interface, prn=sniffProbeReqHandler, timeout=int(args.timeout)) #timeout en secondes


# Affichage
for key in staDic :
    result = key + " : "
    for val in staDic[key]:
        result += val + ", "
    print(result)






