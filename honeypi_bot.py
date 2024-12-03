import subprocess
import logging
import random
from threading import Thread
import socket
from scapy.all import *

# Set up logging to record alerts
logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO)

# Define trusted SCADA and Workstation IPs
trusted_ips = {
    "SCADA": "192.168.90.5",
    "Workstation": "192.168.90.10",  # Add workstation IPs if needed
}

# Define PLC and Honeypot IPs
plc_ip = "192.168.96.2"
honeypot_ips = [
    "192.168.96.114",  # Honeypot IP
    "192.168.96.115",  # Optional second honeypot
]

# Vulnerable protocols and ports
vulnerable_protocols = {
    "Modbus": [502],
    "S7comm": [102],
    "OPC": [135],
}

# Function to send desktop notifications (if using locally)
def send_notification(message):
    logging.info(f"Notification: {message}")  # Replace with notify2.Notification if needed

# Function to detect scanning behavior (e.g., Nmap, Metasploit, etc.)
def detect_scanners(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags

        # Detect Nmap SYN scans
        if flags == "S":  # SYN flag
            logging.warning(f"Possible Nmap scan detected from {src_ip} to {dst_ip}")
            send_notification(f"Possible Nmap scan detected from {src_ip} to {dst_ip}")
            redirect_to_honeypot(src_ip, "Nmap Scan")

# Function to detect and prevent pivot attacks
def detect_pivot(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Pivot attack detection logic: traffic from non-trusted IP to multiple destinations
        if src_ip not in trusted_ips.values() and dst_ip != plc_ip:
            logging.warning(f"Potential pivot attack detected: {src_ip} -> {dst_ip}")
            send_notification(f"Pivot attack detected: {src_ip} -> {dst_ip}")
            redirect_to_honeypot(src_ip, "Pivot Attack")

# Function to handle incoming packets
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto

        # Allow traffic from trusted IPs
        if src_ip in trusted_ips.values():
            logging.info(f"Trusted traffic allowed: {src_ip} -> {dst_ip}")
            return

        # Detect vulnerable PLC traffic
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            for protocol_name, ports in vulnerable_protocols.items():
                if dst_port in ports:
                    logging.warning(f"Vulnerable traffic detected: {src_ip} -> {dst_ip} using {protocol_name}")
                    send_notification(f"Vulnerable traffic detected: {src_ip} -> {dst_ip} using {protocol_name}")

                    # Decide to forward to PLC or redirect to honeypot
                    forward_decision = forward_legitimate_or_redirect(src_ip, dst_ip, protocol_name)
                    if forward_decision == "redirect":
                        redirect_to_honeypot(src_ip, protocol_name)
                    elif forward_decision == "forward":
                        forward_to_plc(src_ip)

        # Check for pivot attacks
        detect_pivot(packet)

        # Detect scanners
        detect_scanners(packet)

# Function to decide if legitimate traffic should go to PLC or Honeypot
def forward_legitimate_or_redirect(src_ip, dst_ip, protocol_name):
    # Example: Decide based on traffic type or prompt the user for manual override
    if src_ip in trusted_ips.values() and dst_ip == plc_ip:
        logging.info(f"Legitimate traffic forwarded: {src_ip} -> {dst_ip} using {protocol_name}")
        return "forward"
    else:
        logging.info(f"Traffic redirected to honeypot: {src_ip} -> {dst_ip} using {protocol_name}")
        return "redirect"

# Function to redirect traffic to the honeypot
def redirect_to_honeypot(src_ip, reason):
    honeypot_ip = random.choice(honeypot_ips)
    logging.info(f"Redirecting traffic from {src_ip} (Reason: {reason}) to honeypot {honeypot_ip}")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", honeypot_ip])

# Function to forward legitimate traffic to the PLC
def forward_to_plc(src_ip):
    logging.info(f"Forwarding traffic from {src_ip} to PLC {plc_ip}")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", plc_ip])

# Function to start sniffing traffic
def start_sniffing():
    logging.info("Starting packet sniffing...")
    sniff(prn=packet_handler, store=0, filter="ip")

# Start the application
if __name__ == "__main__":
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.start()
