#!/usr/bin/env python3.6
#addr2 MAC STA
#addr3 BSSID

from scapy.all import *
import argparse
"""
parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Interface monitoring")
parser.add_argument("timeout", help="Timeout for the sniffing (Secondes)")
args = parser.parse_args()
"""
global staDic
staDic = {}

def sniffHandler(trame):
    if trame.haslayer(Dot11ProbeReq):
        if trame.haslayer(Dot11Elt):
            decodeInfo = trame.info.decode("utf-8")
            if not decodeInfo : #Empty String
                return
            if decodeInfo in staDic:
                staDic[decodeInfo].add(trame.payload.addr2)
            else:
                staDic[decodeInfo] = set([trame.payload.addr2]) #[] dans le set permet d'initialiser avec une valeur sans qu'il le casse en plusieurs caracteres.


sniff(iface='wlo1mon', prn=sniffHandler, timeout=10) #timeout en secondes

for key in staDic :
    result = str(key) + " : "
    for val in staDic[key]:
        result += val + ", "
    print(result)

