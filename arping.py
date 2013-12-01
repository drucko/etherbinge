#!/usr/bin/env python
# note that this script requires scapy to be installed (correctly)
# additionally, it requires root privileges to run.
# Adapted from http://cruft.blogspot.nl/2009/01/arp-ping-using-scapy.html

# set to False if you would like to only have the "CSV" output to console
debug = True

# read CIDR range to scan and network interface to send on from command
import sys,os
if len(sys.argv) != 3:
    print "Usage: arping.py \n  eg: sudo ./arping.py 192.168.1.0/24 eth0"
    sys.exit(1)

# Make sure we have root access
if debug:
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

# suppress annoying warnings about IPv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# load specific modules from scapy
try:
    from scapy.all import srp,Ether,ARP,conf,get_if_hwaddr
except:
    print "please install scapy (correctly) first"
    exit(1)

# use valid hwaddr, even if the NIC is not up
macaddress=get_if_hwaddr(sys.argv[2])

# select output type to console
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

