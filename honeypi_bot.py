import subprocess
import logging
import random
import socket
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

# Function to send desktop notifications (optional)
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

    global trusted_ips, honeypot_ips, logs

    # Main menu
    menu = ["View Logs", "Add Trusted IP", "Remove Trusted IP", "Quit"]
    current_row = 0

    while True:
        stdscr.clear()

        # Render menu
        h, w = stdscr.getmaxyx()
        for idx, row in enumerate(menu):
            x = w // 2 - len(row) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, row, curses.color_pair(1))
            else:
                stdscr.addstr(y, x, row)

        # Handle user input
        key = stdscr.getch()

        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(menu) - 1:
            current_row += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if current_row == 0:  # View Logs
                view_logs(stdscr)
            elif current_row == 1:  # Add Trusted IP
                add_trusted_ip(stdscr)
            elif current_row == 2:  # Remove Trusted IP
                remove_trusted_ip(stdscr)
            elif current_row == 3:  # Quit
                break

        stdscr.refresh()

def view_logs(stdscr):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    stdscr.addstr(0, 0, "Logs:")

    for idx, log in enumerate(logs[-(h - 2):]):
        stdscr.addstr(idx + 1, 0, log[:w - 1])

    stdscr.addstr(h - 1, 0, "Press any key to return...")
    stdscr.getch()

def add_trusted_ip(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter IP to add as trusted: ")
    curses.echo()
    ip = stdscr.getstr(1, 0).decode("utf-8")
    trusted_ips[f"Custom_{len(trusted_ips) + 1}"] = ip
    logs.append(f"Added trusted IP: {ip}")
    curses.noecho()

def remove_trusted_ip(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter IP to remove from trusted: ")
    curses.echo()
    ip = stdscr.getstr(1, 0).decode("utf-8")
    trusted_ips = {key: value for key, value in trusted_ips.items() if value != ip}
    logs.append(f"Removed trusted IP: {ip}")
    curses.noecho()

if __name__ == "__main__":
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.start()

    curses.wrapper(gui)
