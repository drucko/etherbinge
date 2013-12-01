#! /usr/bin/env python
# Note that this script requires scapy to be installed (correctly)
# Additionally, it requires root privileges to run.
# This tool COULD be run together with arping.py to list any ARP resonse with a source not our own.

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

# Start listening for ARP packets on specified interface
import sys,os
if len(sys.argv) != 2:
    print "Usage: arpsniff.py \n  eg: sudo ./arpsniff.py eth0"
    sys.exit(1)

# Make sure we have root access
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

# Suppress annoying warnings about IPv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Load specific modules from scapy
try:
    from scapy.all import ARP,sniff,conf,get_if_hwaddr
except:
    print "please install scapy (correctly) first"
    exit(1)

# Use valid hwaddr, even if the NIC is not up
macaddress=get_if_hwaddr(sys.argv[1])

# Set listening interface
conf.iface = sys.argv[1]

# Print out the ARP.hwsrc (MAC) and ARP.psrc (IP) of ARP request/response not created by us
def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        if pkt[ARP].hwsrc != macaddress:
            return pkt.sprintf("%ARP.hwsrc%,%ARP.psrc%")

# Start sniffing and print to console immediately 
sniff(prn=arp_monitor_callback, filter="arp", store=0)

