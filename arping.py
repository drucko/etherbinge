#!/usr/bin/env python
# Note that this script requires scapy to be installed (correctly)
# Additionally, it requires root privileges to run.
# Adapted from http://cruft.blogspot.nl/2009/01/arp-ping-using-scapy.html.
# This tool MUST be run to elicit ARP resonses without assigning an IP address or creating collisions.
# This tool COULD be run with arpsniff to also find ARP information we did not elicit.

""" http://tools.ietf.org/rfc/rfc5227.txt
RFC 5227, IPv4 Address Conflict Detection, July 2008, page 4-5

In this document, the term 'ARP Probe' is used to refer to an ARP
Request packet, broadcast on the local link, with an all-zero 'sender
IP address'.  The 'sender hardware address' MUST contain the hardware
address of the interface sending the packet.  The 'sender IP address'
field MUST be set to all zeroes, to avoid polluting ARP caches in
other hosts on the same link in the case where the address turns out
to be already in use by another host.  The 'target hardware address'
field is ignored and SHOULD be set to all zeroes.  The 'target IP
address' field MUST be set to the address being probed.  An ARP Probe
conveys both a question ("Is anyone using this address?") and an
implied statement ("This is the address I hope to use.").
"""

# Read CIDR range to scan and network interface to send on from command
import sys,os
if len(sys.argv) != 3:
    print "Usage: arping.py \n  eg: sudo ./arping.py 192.168.1.0/24 eth0"
    sys.exit(1)

# Make sure we have root access
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

# Suppress annoying warnings about IPv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Load specific modules from scapy
try:
    from scapy.all import srp,Ether,ARP,conf,get_if_hwaddr
except:
    print "please install scapy (correctly) first"
    exit(1)

# Use valid hwaddr, even if the NIC is not up
macaddress=get_if_hwaddr(sys.argv[2])

# Set to False if you would like to only have the "CSV" output to console
debug = True
# Select output type to console
if debug:
    conf.verb=4
else:
    conf.verb=0

# Send to Ether.dst broadcast, from our MAC (both Ether.src and ARP.hwsrc), 
# to ARP.hwdst broadcast from IP ARP.psrc 0.0.0.0
# looking from all IP's in given range
ans,unans=srp(Ether(src=macaddress,dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=macaddress,hwdst="00:00:00:00:00:00",psrc="0.0.0.0",pdst=sys.argv[1]),
              timeout=2,iface=str(sys.argv[2]),inter=0.1)

# Output MAC and IP addresses from answers seen
print "MAC,IP"
for snd,rcv in ans:
    print rcv.sprintf("%Ether.src%,%ARP.psrc%")

