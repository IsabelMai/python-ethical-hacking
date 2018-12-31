#!usr/bin/env python

# Import modules
import subprocess
import optparse
import re


# Function to run this script using arguments and options as inputs to change the MAC address of an interface
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC, use --help for more info.")
    return options


# Function to make a system call to change the MAC address of an interface
def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


# Function to check what the current MAC address of an interface is
def get_current_mac(interface):
    # Store the result of the ifconfig system call into ifconfig_result
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # Search through ifconfig_result using a regex to find the MAC address
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address.")


# Get the interface and MAC address that the user inputted
options = get_arguments()

# Check and print the current MAC address of the interface that the user inputted
current_mac = get_current_mac(options.interface)
print("Current MAC = " + str(current_mac))

# Change the MAC address of the interface to what the user inputted
change_mac(options.interface, options.new_mac)

# Check and print the current MAC address of the interface after it has been changed
current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + current_mac)
else:
    print("[-] MAC address did not get changed.")
