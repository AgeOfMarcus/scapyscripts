from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

netSSID = 'testSSID' #Network name
iface = 'wlan1mon' #Monitor interface

# Prepare frame info
dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
              addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
# type=0 - indicate management frame
# subtype=8 - the mgmt frame's subtype is a beacon
# addr1 - dest mac addr
# addr2 - source mac addr
# addr3 - AP mac addr
beacon = Dot11Beacon(cap='ESS+privacy')
# ESS network and it's secured
essid = Dot11Elt(ID='SSID',info=netSSID,len=len(netSSID))
# define ssid
rsn = Dot11Elt(ID='RSNinfo',info=(
        '\x01\x00' #RSN ver 1
        '\x00\x0f\xac\x02' #Group Cipher Suite: 00-0f-ac TKIP
        '\x02\x00' #2 Pairwise Cipher Suites (next 2 lines)
        '\x00\x0f\xac\x04' #AES Cipher
        '\x00\x0f\xac\x02' #TKIP Cipher
        '\x01\x00' #1 Auth key mgmt suite (line below)
        '\x00\x0f\xac\x02' #pre-shared key
        '\x00\x00')) #RSN capabilities (no extra)
# define network as wpa2

# Build and send frame
frame = RadioTap()/dot11/beacon/essid/rsn
frame.show()
print("\nHexDump of frame:")
hexdump(frame)
input("Press [Enter] to start...")

# actually broadcast the frame.
sendp(frame, iface=iface, inter=0.1, loop=1)
# inter=0.1 - broadcast every 100 miliseconds
# loop=1 - loop until program exit
