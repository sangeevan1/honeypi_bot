import subprocess
import logging
import random
import time
from threading import Thread
from scapy.all import *
import curses

# Set up logging to record alerts
logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logs = []  # In-memory log storage for GUI display

# Define the IPs
scada_ip = "192.168.90.5"
plc_ip = "192.168.96.2"
honeypot_ips = ["192.168.96.114", "192.168.96.115"]
trusted_ips = {
    "SCADA": scada_ip,
}

# Vulnerable protocols for attack detection
vulnerable_protocols = {
    "Modbus": [502],
    "S7comm": [102],
    "OPC": [135],
}

# Function to send notifications and log events
def send_notification(message, severity="INFO"):
    if severity == "ALERT":
        logs.append(f"\033[91m{message}\033[0m")  # Red for Alerts
        logging.warning(f"ALERT: {message}")
    else:
        logs.append(message)
        logging.info(message)

# Function to detect scanning behavior (e.g., Nmap)
def detect_scanners(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags
        if flags == "S":  # SYN scan
            message = f"Nmap scan detected from {src_ip} to {dst_ip}"
            send_notification(message, severity="ALERT")
            redirect_to_honeypot(src_ip, "Nmap Scan")

# Function to detect pivot attacks
def detect_pivot(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip not in trusted_ips.values() and dst_ip != plc_ip:
            message = f"Potential pivot attack detected: {src_ip} -> {dst_ip}"
            send_notification(message, severity="ALERT")
            redirect_to_honeypot(src_ip, "Pivot Attack")

# Function to detect malicious commands (example: Modbus, S7comm)
def detect_vulnerable_traffic(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        for protocol_name, ports in vulnerable_protocols.items():
            if dst_port in ports:
                message = f"Vulnerable traffic detected: {src_ip} -> {dst_ip} ({protocol_name})"
                send_notification(message, severity="ALERT")
                forward_decision = forward_or_redirect(src_ip, dst_ip, protocol_name)
                if forward_decision == "redirect":
                    redirect_to_honeypot(src_ip, protocol_name)
                elif forward_decision == "forward":
                    forward_to_plc(src_ip)

# Function to decide whether to forward or redirect traffic
def forward_or_redirect(src_ip, dst_ip, protocol_name):
    if src_ip in trusted_ips.values() and dst_ip == plc_ip:
        send_notification(f"Forwarding legitimate traffic: {src_ip} -> {dst_ip} ({protocol_name})")
        return "forward"
    else:
        send_notification(f"Redirecting traffic to honeypot: {src_ip} -> {dst_ip} ({protocol_name})", severity="ALERT")
        return "redirect"

# Redirect traffic to honeypot
def redirect_to_honeypot(src_ip, reason):
    honeypot_ip = random.choice(honeypot_ips)
    message = f"Redirecting {src_ip} to honeypot {honeypot_ip} (Reason: {reason})"
    send_notification(message, severity="ALERT")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", honeypot_ip])

# Forward traffic to PLC
def forward_to_plc(src_ip):
    message = f"Forwarding traffic from {src_ip} to PLC {plc_ip}"
    send_notification(message)
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", src_ip, "-j", "DNAT", "--to-destination", plc_ip])

# Function to monitor traffic
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Only allow traffic from trusted IPs
        if src_ip in trusted_ips.values():
            logs.append(f"Trusted traffic allowed: {src_ip} -> {dst_ip}")
            return
        
        # Detect vulnerable traffic (attacks)
        detect_vulnerable_traffic(packet)
        detect_scanners(packet)
        detect_pivot(packet)

# Start packet sniffing in a separate thread
def start_sniffing():
    sniff(prn=packet_handler, store=0, filter="ip")

# Function to view logs
def view_logs_menu(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Current Traffic Logs (Last 10 Entries):", curses.A_BOLD)
    stdscr.refresh()

    y = 2
    for log in logs[-10:]:  # Show last 10 logs
        stdscr.addstr(y, 0, log)
        y += 1

    stdscr.refresh()

    # Wait for user input to go back to the main menu
    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

# Terminal GUI
def gui(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(500)

    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLUE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Display application title
        stdscr.addstr(0, (w // 2) - 8, "HoneyPi Bot", curses.A_BOLD | curses.color_pair(1))
        stdscr.addstr(1, (w // 2) - 17, "Real-time Traffic Monitoring", curses.A_BOLD)
        stdscr.addstr(2, (w // 2) - 8, "Author: Sangeevan", curses.A_BOLD)

        # Menu options
        menu = [
            "1. Set Trusted IP",
            "2. View Logs",
            "3. Exit"
        ]
        for idx, option in enumerate(menu):
            stdscr.addstr(h // 2 + idx - 2, (w // 2) - len(option) // 2, option, curses.A_BOLD)

        # Handle user input
        key = stdscr.getch()
        if key == ord('q'):
            break
        elif key == ord('1'):
            # Set trusted IP
            set_trusted_ip_menu(stdscr)
        elif key == ord('2'):
            # View logs
            view_logs_menu(stdscr)

        stdscr.refresh()

# Submenu for setting trusted IP
def set_trusted_ip_menu(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter IP address to add as trusted:", curses.A_BOLD)
    stdscr.refresh()
    curses.echo()
    
    # Wait for user input
    ip = stdscr.getstr(1, 0).decode("utf-8")
    trusted_ips["User IP"] = ip
    send_notification(f"Added trusted IP: {ip}")

    curses.noecho()

    # Wait for 'q' to return to main menu
    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

# Start sniffing in a background thread
sniffing_thread = Thread(target=start_sniffing)
sniffing_thread.daemon = True
sniffing_thread.start()

# Start the curses-based terminal interface
curses.wrapper(gui)
