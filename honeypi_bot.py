import os
import sys
import threading
import time
from scapy.all import sniff, IP, TCP

# Honeypot and PLC IPs (modify as per your system)
HONEYPOT_IP = '192.168.96.114'
PLC_IP = '192.168.96.2'

# List to store allowed and disallowed IPs
ALLOWED_IPS = []
DISALLOWED_IPS = []

# Vulnerable ports to monitor (e.g., Modbus, SMB)
VULNERABLE_PORTS = [502, 135, 80]

# Global variable for alert messages
alert_message = ""

# Function to display the IP table in a user-friendly format
def display_ip_table():
    print("\nAllowed IPs:".center(50, "="))
    print(f"{'IP Address':<20} {'Status':<10}")
    print("-" * 30)
    for ip in ALLOWED_IPS:
        print(f"{ip:<20} {'Allowed':<10}")
    
    print("\nDisallowed IPs:".center(50, "="))
    print(f"{'IP Address':<20} {'Status':<10}")
    print("-" * 30)
    for ip in DISALLOWED_IPS:
        print(f"{ip:<20} {'Disallowed':<10}")

# Function to check if an IP is allowed
def is_ip_allowed(ip):
    return ip in ALLOWED_IPS

# Function to handle redirection of traffic to the honeypot
def redirect_to_honeypot(src_ip):
    print(f"Redirecting traffic from {src_ip} to Honeypot: {HONEYPOT_IP}")
    # Apply iptables rule to redirect traffic to Honeypot
    os.system(f"sudo iptables -t nat -A PREROUTING -s {src_ip} -j DNAT --to-destination {HONEYPOT_IP}")

# Function to handle logging of alerts
def log_alert(message):
    global alert_message
    alert_message = message
    print(f"ALERT: {alert_message}")
    # You can log it to a file as well if needed
    with open('honeypot_alerts.log', 'a') as log_file:
        log_file.write(f"{time.ctime()}: {message}\n")

# Function to analyze each packet and detect attacks
def analyze_packet(packet):
    global alert_message

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if dst_ip == PLC_IP and not is_ip_allowed(src_ip):
            # Detect vulnerable traffic (e.g., Modbus port 502)
            if packet.haslayer(TCP) and packet[TCP].dport in VULNERABLE_PORTS:
                alert_message = f"Vulnerable traffic detected from {src_ip} to PLC on port {packet[TCP].dport}"
                log_alert(alert_message)
                redirect_to_honeypot(src_ip)
            else:
                # If allowed traffic is targeting the PLC, just log it
                print(f"Allowed traffic from {src_ip} to PLC.")

        # Handle honeypot traffic (no blocking)
        if dst_ip == HONEYPOT_IP:
            print(f"Traffic to Honeypot from {src_ip}: {packet.summary()}")

# Function to monitor network traffic continuously in a background thread
def network_monitoring():
    print("Starting network monitoring in background...")
    sniff(prn=analyze_packet, store=0, timeout=60)  # Monitor for 60 seconds per sniff

# Function to handle user inputs for adding/removing IPs
def handle_ip_management():
    while True:
        print("\n1. View Allowed/Disallowed IP Table")
        print("2. Add Allowed IP")
        print("3. Add Disallowed IP")
        print("4. Remove Allowed IP")
        print("5. Remove Disallowed IP")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            display_ip_table()
        elif choice == "2":
            ip = input("Enter IP to allow: ")
            if ip not in ALLOWED_IPS and ip not in DISALLOWED_IPS:
                ALLOWED_IPS.append(ip)
                log_alert(f"IP {ip} added to allowed list.")
            else:
                print(f"IP {ip} is already in the list.")
        elif choice == "3":
            ip = input("Enter IP to disallow: ")
            if ip not in ALLOWED_IPS and ip not in DISALLOWED_IPS:
                DISALLOWED_IPS.append(ip)
                log_alert(f"IP {ip} added to disallowed list.")
            else:
                print(f"IP {ip} is already in the list.")
        elif choice == "4":
            ip = input("Enter IP to remove from allowed list: ")
            if ip in ALLOWED_IPS:
                ALLOWED_IPS.remove(ip)
                log_alert(f"IP {ip} removed from allowed list.")
            else:
                print(f"IP {ip} not found in allowed list.")
        elif choice == "5":
            ip = input("Enter IP to remove from disallowed list: ")
            if ip in DISALLOWED_IPS:
                DISALLOWED_IPS.remove(ip)
                log_alert(f"IP {ip} removed from disallowed list.")
            else:
                print(f"IP {ip} not found in disallowed list.")
        elif choice == "6":
            break
        else:
            print("Invalid choice, please try again.")

# Main function to run the program
def main():
    # Start the network monitoring in a separate thread
    monitoring_thread = threading.Thread(target=network_monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()

    # Start handling user input for IP management
    handle_ip_management()

if __name__ == "__main__":
    main()
