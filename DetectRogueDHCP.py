#! /usr/bin/env python

from scapy.all import *

def check(interfaceName):
  conf.checkIPaddr = False
  fam,hw = get_if_raw_hwaddr(interfaceName)
  dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
  ans, unans = srp(dhcp_discover, multi=True, timeout=3)      # Press CTRL-C after several seconds --> timeout :)
  for p in ans: print(p[1][Ether].src, p[1][IP].src)


interfaces = ["ens160","ens192","ens224","ens256"]
for i in interfaces:
  print("===================")
  print("Checking: "+i)
  check(i)
