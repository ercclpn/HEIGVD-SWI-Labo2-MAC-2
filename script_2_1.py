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

global bssidLinkSta
bssidLinkSta = {}


def sniffProbeReqHandler(trame):
    if trame.haslayer(Dot11ProbeReq):
        if trame.haslayer(Dot11Elt):
            if not trame.addr1 == 'ff:ff:ff:ff:ff:ff':
                if trame.addr1 in bssidLinkSta:
                    bssidLinkSta[trame.addr1].add(trame.addr2)
                else:
                    bssidLinkSta[trame.addr1] = set([trame.addr2])
            else:
                return
            decodeInfo = trame.info.decode("utf-8")
            if not decodeInfo : #Empty String
                if decodeInfo in staDic:
                    staDic[decodeInfo].add(trame.addr2)
                else:
                    staDic[decodeInfo] = set([trame.addr2]) #[] dans le set permet d'initialiser avec une valeur sans qu'il le casse en plusieurs caracteres.

def sniffAPHandler(trame):
    if trame.haslayer(Dot11Beacon):
        if trame.haslayer(Dot11Elt):
            decodeInfo = trame.info.decode("utf-8")
            if decodeInfo in staDic and not trame.addr2 in bssidLinkSta :
               bssidLinkSta[trame.addr2] = staDic[decodeInfo]



sniff(iface='wlo1mon', prn=sniffProbeReqHandler, timeout=30) #timeout en secondes

for key in staDic :
    result = str(key) + " : "
    for val in staDic[key]:
        result += val + ", "
    print(result)

sniff(iface='wlo1mon', prn=sniffAPHandler, timeout=30)


for key in bssidLinkSta:
    print(key + "   " + bssidLinkSta[key])






