#!/usr/bin/env python
# http://www.attackvector.org/network-discovery-via-dhcp-using-python-scapy/
# by Matt
import sys
from scapy.all import *
 
ipv6_enabled = 0
conf.verb=0
conf.checkIPaddr = False
fam,hw = get_if_raw_hwaddr(conf.iface)
 
def dhcp_discover(resp):
    print "Source: " +resp[Ether].src
    print "Dest: " +resp[Ether].dst
 
    for opt in resp[DHCP].options:
        if opt == 'end':
            break
        elif opt == 'pad':
            break
        print opt
    sys.exit(0)
 
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover")]),count=3)
sniff(filter="udp and (port 67 or 68)", prn=dhcp_discover, store=1)
