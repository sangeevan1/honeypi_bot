import subprocess
import logging
import random
from threading import Thread
from scapy.all import *
import curses
import time

# Set up logging to record alerts
logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO)

# Default configuration
trusted_ips = {
    "SCADA": "192.168.90.5",
    "Workstation": "192.168.90.10",
}

plc_ip = "192.168.96.2"
honeypot_ips = [
    "192.168.96.114",
    "192.168.96.115",
]

vulnerable_protocols = {
    "Modbus": [502],
    "S7comm": [102],
    "OPC": [135],
}

logs = []  # In-memory log storage for GUI display

# Function to send notifications
def send_notification(message):
    logging.info(f"Notification: {message}")
    logs.append(f"Notification: {message}")

# Function to detect scanning behavior
def detect_scanners(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags
        if flags == "S":
            message = f"Possible Nmap scan detected from {src_ip} to {dst_ip}"
            logging.warning(message)
            send_notification(message)
            redirect_to_honeypot(src_ip, "Nmap Scan")

# Function to detect pivot attacks
def detect_pivot(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip not in trusted_ips.values() and dst_ip != plc_ip:
            message = f"Potential pivot attack detected: {src_ip} -> {dst_ip}"
            logging.warning(message)
            send_notification(message)
            redirect_to_honeypot(src_ip, "Pivot Attack")

# Function to handle incoming packets
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto

        # Allow traffic from trusted IPs
        if src_ip in trusted_ips.values():
            logs.append(f"Trusted traffic allowed: {src_ip} -> {dst_ip}")
            return

        # Detect vulnerable traffic
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            for protocol_name, ports in vulnerable_protocols.items():
                if dst_port in ports:
                    message = f"Vulnerable traffic detected: {src_ip} -> {dst_ip} ({protocol_name})"
                    logging.warning(message)
                    send_notification(message)
                    forward_decision = forward_legitimate_or_redirect(src_ip, dst_ip, protocol_name)
                    if forward_decision == "redirect":
                        redirect_to_honeypot(src_ip, protocol_name)
                    elif forward_decision == "forward":
                        forward_to_plc(src_ip)

        detect_pivot(packet)
        detect_scanners(packet)

# Decide whether to forward or redirect
def forward_legitimate_or_redirect(src_ip, dst_ip, protocol_name):
    if src_ip in trusted_ips.values() and dst_ip == plc_ip:
        logs.append(f"Forwarding legitimate traffic: {src_ip} -> {dst_ip} ({protocol_name})")
        return "forward"
    else:
        logs.append(f"Redirecting traffic to honeypot: {src_ip} -> {dst_ip} ({protocol_name})")
        return "redirect"

# Redirect traffic to honeypot
def redirect_to_honeypot(src_ip, reason):
    honeypot_ip = random.choice(honeypot_ips)
    logs.append(f"Redirecting {src_ip} to honeypot {honeypot_ip} (Reason: {reason})")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", honeypot_ip])

# Forward legitimate traffic to PLC
def forward_to_plc(src_ip):
    logs.append(f"Forwarding traffic from {src_ip} to PLC {plc_ip}")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", plc_ip])

# Start sniffing packets
def start_sniffing():
    sniff(prn=packet_handler, store=0, filter="ip")

# Terminal GUI
def gui(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(500)

    global logs

    while True:
        stdscr.clear()

        # Display application name and author
        stdscr.addstr(0, 0, "HoneyPi_bot - Real-time Traffic Monitoring")
        stdscr.addstr(1, 0, "Author: Sangeevan")

        # Display logs
        log_start_line = 3
        h, w = stdscr.getmaxyx()
        for idx, log in enumerate(logs[-(h - log_start_line - 1):]):
            stdscr.addstr(log_start_line + idx, 0, log[:w - 1])

        # Footer
        stdscr.addstr(h - 1, 0, "Press 'q' to exit the log viewer...")

        # Handle user input
        key = stdscr.getch()
        if key == ord('q'):
            break

        stdscr.refresh()
        time.sleep(0.5)

if __name__ == "__main__":
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.start()

    curses.wrapper(gui)
