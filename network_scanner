#!/usr/bin/env python

# Import modules
import optparse
import scapy.all as scapy


# Function to run this script using an argument and option as input to scan for MAC addresses of the input
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="IP Address or range to find corresponding MAC address")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an IP address or range, use --help for more info.")
    return options


# Function to get MAC addresses of certain IP addresses (same functionality as arping method)
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # Gets a list of all the ARP packets that were successfully sent and replied to, and the response packets
    # Note: [1] would be used to retrieve the unanswered_list
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        # Gets the source IP address and MAC address of the response packets and puts it in a dictionary
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # Add the dictionary to the overall list of all IP and MAC addresses of clients that responded
        clients_list.append(client_dict)
    return clients_list


# Function to iterate through list results
def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)
