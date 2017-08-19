from scapy import *

def packet_callback(packet):
    print packet.show()

p = sniff(iface='eth0', timeout=1000, prn=packet_callback)
