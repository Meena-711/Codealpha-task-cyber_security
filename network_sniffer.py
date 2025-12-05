import sys
import logging
from scapy.all import sniff, IP, TCP, UDP, Raw, conf, show_interfaces
from scapy.error import Scapy_Exception

# Set Scapy's logging to suppress excessive output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# IANA Protocol Number Mapping for IP Layer
PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

def get_protocol_name(proto_number):
    """Translates the IP protocol number into a human-readable name."""
    return PROTOCOL_MAP.get(proto_number, f"Other ({proto_number})")

def packet_handler(packet):
    """This function is called for every packet captured."""
    
    # 1. Check for the IP Layer (Layer 3)
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_num = packet[IP].proto
        protocol = get_protocol_name(protocol_num)
        
        # Print basic IP information
        print("-" * 50)
        print(f"[{protocol} Packet]")
        print(f"Source IP: {src_ip:<15} -> Destination IP: {dst_ip}")
        print(f"Protocol (IP Layer): {protocol}")

        # 2. Check for Transport Layer (Layer 4)
        if TCP in packet:
            # TCP details
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port:<10} -> Destination Port: {dst_port} (TCP)")
            print(f"TCP Flags: {packet[TCP].flags}")

        elif UDP in packet:
            # UDP details
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port:<10} -> Destination Port: {dst_port} (UDP)")

        # 3. Check for Payload (Application Layer Data)
        if Raw in packet:
            # Display the first 100 characters of the payload in hex
            payload_hex = packet[Raw].load.hex()
            print(f"Payload (Hex): {payload_hex[:100]}...")
        else:
            print("No visible application payload.")
            
def main():
    """Find interface and start sniffing."""
    print("=" * 50)
    print("      Basic Network Packet Sniffer (Scapy)")
    print("=" * 50)
    
    # On Windows, Scapy often needs an explicit interface name.
    # We first show the user what interfaces are available.
    print("Checking available interfaces...")
    try:
        show_interfaces()
        
        # Prompt user to input the correct interface name
        interface_name = input("\nEnter the Name of the interface to sniff on (e.g., Ethernet0, Wi-Fi, or the full GUID): ")
        
        if not interface_name.strip():
             print("[!] Interface name cannot be empty. Exiting.")
             sys.exit(1)

        print(f"\n[*] Starting sniffer on interface: {interface_name}")
        print("[*] Listening for all traffic. Press Ctrl+C to stop.")
        
        # Start sniffing indefinitely (count=0)
        sniff(
            iface=interface_name.strip(),
            prn=packet_handler, # The function to call for each packet
            store=0,            # Don't store packets in memory
            count=0             # Sniff indefinitely
        )

    except PermissionError:
        print("\n[!!!] ERROR: Permission denied. You MUST run this script as **Administrator**.")
    except Scapy_Exception as e:
        print(f"\n[!!!] ERROR: Scapy failed to initialize or the interface name is incorrect: {e}")
        print("Please verify the interface name you entered and ensure Npcap is properly installed.")
    except KeyboardInterrupt:
        print("\n[INFO] Sniffer stopped by user (Ctrl+C).")
    
if __name__ == "__main__":
    main()
