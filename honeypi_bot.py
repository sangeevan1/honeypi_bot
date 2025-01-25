import os
import time
import json
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, ICMP
from prettytable import PrettyTable
from colorama import Fore, Style, init
import ipaddress

# Initialize Colorama for colored output
init(autoreset=True)

# Log file paths
PLC_LOGS = "plc_logs.json"
HONEYPOT_LOGS = "honeypot_logs.json"

# Honeypot IP Address
HONEYPOT_IP = "192.168.96.114"

# Suricata log file location
SURICATA_LOG_FILE = "/var/log/suricata/eve.json"

# Set up logging for events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def write_log(file, log_data):
    """Write log data to a JSON file with exception handling."""
    try:
        with open(file, "a") as f:
            f.write(json.dumps(log_data) + "\n")
    except Exception as e:
        logging.error(f"Error writing to log file: {e}")

def start_suricata():
    """Start Suricata with the configuration file."""
    print(Fore.GREEN + "Starting Suricata...")
    os.system("sudo suricata -c /etc/suricata/suricata.yaml -i eth0 &")
    print(Fore.GREEN + "Suricata is running.")

def sniff_filtered_traffic(packet_count=100):
    """Sniff and handle a specific number of filtered packets."""
    print(Fore.GREEN + f"Sniffing {packet_count} relevant packets...")
    sniff(prn=handle_packet, count=packet_count, store=False, filter="tcp port 502 or tcp port 20000", iface="eth0")

def handle_packet(packet):
    """Handle each sniffed packet."""
    src_ip = packet[IP].src if IP in packet else None
    dest_ip = packet[IP].dst if IP in packet else None
    
    if packet.haslayer(TCP):
        handle_tcp_packet(packet, src_ip, dest_ip)
    elif packet.haslayer(ICMP):
        handle_icmp_packet(packet, src_ip, dest_ip)

def handle_tcp_packet(packet, src_ip, dest_ip):
    """Handle TCP packets and apply more refined thresholds."""
    if packet[TCP].flags == "S":  # SYN scan detection (NMAP)
        logging.warning(f"Potential NMAP Scan Detected from {src_ip} to {dest_ip}")
        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert": "Potential NMAP Scan",
            "src_ip": src_ip,
            "dest_ip": dest_ip
        }
        write_log(PLC_LOGS, log_data)
        redirect_to_honeypot(src_ip)
    elif packet[TCP].dport == 502:  # MODBUS traffic
        handle_modbus_command_injection(packet, src_ip, dest_ip)

def handle_modbus_command_injection(packet, src_ip, dest_ip):
    """Detect MODBUS command injections based on payload content."""
    if "cmd=" in str(packet[TCP].payload):  # Look for command injection patterns
        logging.error(f"MODBUS Command Injection Attempt Detected from {src_ip} to {dest_ip}")
        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert": "MODBUS Command Injection Attempt",
            "src_ip": src_ip,
            "dest_ip": dest_ip
        }
        write_log(PLC_LOGS, log_data)
        redirect_to_honeypot(src_ip)

def handle_icmp_packet(packet, src_ip, dest_ip):
    """Handle ICMP packets, such as ping sweeps."""
    if packet[ICMP].type == 8:  # Ping sweep (ICMP Echo Request)
        logging.warning(f"Potential Ping Sweep Detected from {src_ip} to {dest_ip}")
        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert": "Potential Ping Sweep",
            "src_ip": src_ip,
            "dest_ip": dest_ip
        }
        write_log(PLC_LOGS, log_data)
        redirect_to_honeypot(src_ip)

def redirect_to_honeypot(ip):
    """Redirect malicious traffic to the honeypot."""
    print(Fore.YELLOW + f"Redirecting IP {ip} to honeypot...")
    os.system(f"sudo iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}")
    honeypot_log = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip,
        "action": "Redirected to honeypot"
    }
    write_log(HONEYPOT_LOGS, honeypot_log)
    print(Fore.GREEN + f"IP {ip} successfully redirected.")

def manage_ips():
    """Block or unblock IP addresses."""
    print("\nIP Management")
    print("1. Block IP")
    print("2. Unblock IP")
    print("3. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        ip = input("Enter IP to block: ")
        if validate_ip(ip):
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            print(Fore.RED + f"IP {ip} blocked.")
        else:
            print(Fore.RED + "Invalid IP format.")
    elif choice == "2":
        ip = input("Enter IP to unblock: ")
        if validate_ip(ip):
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            print(Fore.GREEN + f"IP {ip} unblocked.")
        else:
            print(Fore.RED + "Invalid IP format.")
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice.")

def validate_ip(ip):
    """Validate the format of an IP address."""
    try:
        ipaddress.ip_address(ip)  # Try to create an IP address object
        return True
    except ValueError:
        return False

def view_logs():
    """View saved logs."""
    print("\nLog Viewer")
    print("1. View PLC Logs")
    print("2. View Honeypot Logs")
    print("3. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        print(Fore.GREEN + "PLC Logs:")
        display_logs(PLC_LOGS)
    elif choice == "2":
        print(Fore.GREEN + "Honeypot Logs:")
        display_logs(HONEYPOT_LOGS)
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice.")

def display_logs(file):
    """Display logs from a specified file."""
    if not os.path.exists(file):
        print(Fore.RED + "No logs available.")
        return

    with open(file, "r") as f:
        for line in f:
            log = json.loads(line.strip())
            print(json.dumps(log, indent=2))

def track_honeypot():
    """Track traffic redirected to the honeypot."""
    print(Fore.GREEN + "Honeypot Traffic:")
    display_logs(HONEYPOT_LOGS)

def main():
    """Main function to run the SOC."""
    start_suricata()
    while True:
        print("\n--- SOC Menu ---")
        print("1. Monitor Traffic (PLC)")
        print("2. Manage IPs (Block/Unblock)")
        print("3. View Logs")
        print("4. Track Honeypot Traffic")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            sniff_filtered_traffic()
        elif choice == "2":
            manage_ips()
        elif choice == "3":
            view_logs()
        elif choice == "4":
            track_honeypot()
        elif choice == "5":
            print(Fore.YELLOW + "Exiting SOC...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
