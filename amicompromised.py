#make sure you install the following plugins
#  1. NPCAP
#  2. Scapy, using python setup.py install
#  3. pyreadline
#    ^^ Above programs referenced in Scapy documentation, under platform-specific instructions, Windows
from scapy.all import *
import re
import sys

#this is the callback to retrieve packet data
def packet_callback(packet):    
    print packet.show()

#this will silence stdout
def silence_stdout():
	new_target = open(os.devnull, "w")
	old_target, sys.stdout = sys.stdout, new_target
	try:
		yield new_target
	finally:
		sys.stdout = old_target

#perform sniffing on interface, and use lambda to also print out to PCAP
silence_stdout(p = sniff(timeout=1000, prn=packet_callback))


#set up a search regex for blacklisted IP addresses
#search = re.compile(r'(:\d\d\d\d\d)|(:\d\d\d\d)|(:\d\d\d)')
search = re.compile(r'54\.186\.180\.223.*')
answer = search.findall(p)
print answer

#pcap output
wrpcap('packets.pcap', p)

