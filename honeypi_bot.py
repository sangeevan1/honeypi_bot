from scapy.all import *
import subprocess
import logging
import random
from threading import Thread
import socket

# Set up logging to record alerts
logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO)

# Define trusted SCADA and PLC IPs (adjust with actual IPs)
scada_ip = "192.168.90.5"
plc_ip = "192.168.96.2"

# Honeypot IP (since you specified this IP)
honeypot_ip = '192.168.96.114'

# Define pre-configured rules for vulnerable PLC traffic (like Modbus, S7comm, OPC)
vulnerable_protocols = {
    "Modbus": [502],   # Modbus typically runs on TCP port 502
    "S7comm": [102],   # S7comm typically runs on TCP port 102 (Siemens S7)
    "OPC": [135],      # OPC typically runs on TCP port 135
}

# Function to log alerts to console and file
def log_alert(message):
    # Log to file
    logging.warning(message)
    # Print to terminal
    print(message)

# Function to detect scanning behavior (e.g., Nmap, Metasploit, other scanners)
def detect_scanners(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags
        dport = packet[TCP].dport

        # Check for Nmap SYN scan (common flag pattern)
        if flags == "S":  # SYN flag typically used in Nmap scans
            log_alert(f"Possible Nmap scan detected from {src_ip} to {dst_ip} using SYN packets!")
            redirect_to_honeypot(src_ip, "Nmap Scan")

        # Detect Metasploit traffic (example: detecting known Metasploit scanning behavior)
        if dport == 4444:  # Metasploit's default reverse shell port
            log_alert(f"Possible Metasploit scan or exploit attempt from {src_ip} to {dst_ip}!")
            redirect_to_honeypot(src_ip, "Metasploit Exploit")

# Function to handle incoming packets
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto
        payload = str(packet.payload)

        # Check for vulnerable PLC traffic (Modbus, S7comm, OPC)
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport

            for protocol_name, ports in vulnerable_protocols.items():
                if dst_port in ports:
                    log_alert(f"Vulnerable PLC traffic detected: {src_ip} -> {dst_ip} using {protocol_name}!")
                    redirect_to_honeypot(src_ip, protocol_name)

        # Monitor legitimate traffic between SCADA and PLC
        elif src_ip == scada_ip and dst_ip == plc_ip:
            log_alert(f"Legitimate Modbus traffic: {src_ip} -> {dst_ip}")
        else:
            log_alert(f"Other traffic: {src_ip} -> {dst_ip}")

        # Call scanner detection function
        detect_scanners(packet)

# Function to redirect traffic to the honeypot
def redirect_to_honeypot(src_ip, reason):
    # Use the fixed honeypot IP
    logging.info(f"Redirecting traffic from {src_ip} (Reason: {reason}) to honeypot {honeypot_ip}.")
    
    # Use iptables to redirect traffic to the honeypot
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", honeypot_ip])

# Function to start the sniffing process
def start_sniffing():
    log_alert("Starting packet sniffing...")
    sniff(prn=packet_handler, store=0, filter="ip")

# Function to handle traffic redirection with load balancing (modified to use a fixed honeypot)
def handle_request(client_socket):
    try:
        # Use the fixed honeypot IP for all traffic redirection
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_socket.connect((honeypot_ip, 80))  # Assuming honeypot is listening on port 80
        
        # Receive data from client
        request = client_socket.recv(1024)
        
        # Send the data to the honeypot
        forward_socket.sendall(request)
        
        # Receive the response from the honeypot
        response = forward_socket.recv(1024)
        
        # Send the response back to the client
        client_socket.sendall(response)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        forward_socket.close()

# Set up the server to listen for incoming connections and perform load balancing
def start_load_balancer(host='0.0.0.0', port=80):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Load Balancer is running on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        
        # Start a new thread to handle the request and forward it
        request_thread = Thread(target=handle_request, args=(client_socket,))
        request_thread.start()

if __name__ == "__main__":
    # Start traffic sniffing and load balancer in separate threads
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.start()

    load_balancer_thread = Thread(target=start_load_balancer)
    load_balancer_thread.start()
