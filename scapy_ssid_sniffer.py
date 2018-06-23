from scapy.all import *

ap_list = []

def PacketHandler(pkt):
        if pkg.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8:
                        if not pkt.addr2 in ap_list:
                                ap_list.append(pkt.addr2)
                                print("AP MAC: %s with SSID: %s" % (pkt.addr2,pkt.info))

sniff(iface="wlan1mon", prn=PacketHandler)
