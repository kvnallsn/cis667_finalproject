#!/usr/bin/env python
# Reads in a pcap file and produces output for the neural network

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp, udp
import binascii
import icmp
import csv
import sys

def is_syn(tcp_packet):
    if 0x00 == tcp_packet.urg and \
       0x00 == tcp_packet.ack and \
       0x00 == tcp_packet.psh and \
       0x00 == tcp_packet.rst and \
       0x01 == tcp_packet.syn and \
       0x00 == tcp_packet.fin:
        return True
    else:
        return False

def is_ack(tcp_packet):
    if 0x00 == tcp_packet.urg and \
       0x01 == tcp_packet.ack and \
       0x00 == tcp_packet.psh and \
       0x00 == tcp_packet.rst and \
       0x00 == tcp_packet.syn and \
       0x00 == tcp_packet.fin:
        return True
    else:
        return False

def is_rst(tcp_packet):
    if 0x00 == tcp_packet.urg and \
       0x00 == tcp_packet.ack and \
       0x00 == tcp_packet.psh and \
       0x01 == tcp_packet.rst and \
       0x00 == tcp_packet.syn and \
       0x00 == tcp_packet.fin:
        return True
    else:
        return False

def is_fin(tcp_packet):
    if 0x00 == tcp_packet.urg and \
       0x00 == tcp_packet.ack and \
       0x00 == tcp_packet.psh and \
       0x00 == tcp_packet.rst and \
       0x00 == tcp_packet.syn and \
       0x01 == tcp_packet.fin:
        return True
    else:
        return False

def chunks(l, n):
    """Yield successive n-sized chunks from l"""
    for i in xrange(0, len(l), n):
        yield l[i:i + n]

def analyze(pcapfile, malicious, outfile):
    testcap = open(pcapfile, 'rb')
    capfile = savefile.load_savefile(testcap, verbose=True)

    if len(capfile.packets) < 101:
        """ Need at least 100 packets to analyze the traffic """
        return False                

    for packets in chunks(capfile.packets, 100):
        # Array to contain the different packet types
        # In order:
        # 0 - ARP
        # 1 - SYN
        # 2 - ACK
        # 3 - RST
        # 4 - FIN
        # 5 - ECHO Request
        # 6 - ECHO Reply
        # 7 - 1 for Malicious, 0 for safe
        ranked = [0, 0, 0, 0, 0, 0, 0, 0]   
        for pkt in packets:
            eth_frame = ethernet.Ethernet(pkt.raw())
            if eth_frame.type == 0x0800:
                ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
                if ip_packet.p == 0x06:
                    tcp_packet = tcp.TCP(binascii.unhexlify(ip_packet.payload))

                    if is_syn(tcp_packet):
                        ranked[1] += 1
                    elif is_ack(tcp_packet):
                        ranked[2] += 1
                    elif is_rst(tcp_packet):
                        ranked[3] += 1
                    elif is_fin(tcp_packet):
                        ranked[4] += 1
                elif ip_packet.p == 0x01 and ip_packet.flags == 0x01:
                    ranked[5] += 1
                elif ip_packet.p == 0x01:
                    icmp_packet = icmp.ICMP(binascii.unhexlify(ip_packet.payload))
                    
                    if icmp_packet.type == 0x08:
                        ranked[5] += 1
                    elif icmp_packet.type == 0x00:
                        ranked[6] += 1
            elif eth_frame.type == 0x0806:
                ranked[0] += 1

        if malicious == True:
            ranked[7] = 1

        with open(outfile, 'a') as f:
            writer = csv.writer(f)
            writer.writerow(ranked)

    return True

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print 'usage: %s <filename> <malicious|safe> <outfile>' % sys.argv[0]
        sys.exit()

    #if sys.argv[2] == "malicious":
    #    bad = 1

    analyze(sys.argv[1], sys.argv[2] == "malicious", sys.argv[3])

