#!/usr/bin/env python

import sys
from scapy.all import *

p = fragment(IP(dst="192.168.1.12")/ICMP()/("X"*60000))
ls(p)

#print "Sending packets in 0.3 second intervals for timeout of 4 secs"
ans,unans = srloop(p, inter=1, retry=2, timeout=8)
#print "Summary of answered & unanswered packets"
#ans.summary()
#unans.summary()
#print "source port flags in response"
#ans.make_table(lambda(s,r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
