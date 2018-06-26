from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump
import random

filename = input("Enter path to text file with list of SSIDS: ")
try:
        fd = open(filename,"r")
        ssids = fd.read().split("\n")
        fd.close()
except:
        print("Cannot open file")
        exit(0)

def random_mac():
        mac = [0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

def gen_packet(ssid,source_mac):
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                      addr2=source_mac, addr3=source_mac)
        beacon = Dot11Beacon(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        rsn = Dot11Elt(ID="RSNinfo", info=(
                '\x01\x00'
                '\x00\x0f\xac\x02'
                '\x02\x00'
                '\x00\x0f\xac\x04'
                '\x00\x0f\xac\x02'
                '\x01\x00'
                '\x00\x0f\xac\x02'
                '\x00\x00'))
        frame = RadioTap()/dot11/beacon/essid/rsn
        return frame

def send_frame(frame, iface="wlan1mon"):
        sendp(frame, iface=iface)

if __name__ == "__main__":
        iface = input("Enter interface with monitor mode: ")
        frames = []
        for i in ssids:
                pkt = gen_packet(i,random_mac())
                frames.append(pkt)
        print("Press 'CTRL+C' to stop broadcasting.")
        while True:
                try:
                        for pkt in frames:
                                send_frame(pkt,iface=iface)
                except KeyboardInterrupt:
                        break
