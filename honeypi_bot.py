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
alerts = []  # For storing alerts

# Function to send notifications
def send_notification(message):
    logging.info(f"Notification: {message}")
    logs.append(f"Notification: {message}")
    alerts.append(f"ALERT: {message}")  # Store alert to show in the main menu

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

# Function to set a trusted IP
def set_trusted_ip(ip_address, name):
    trusted_ips[name] = ip_address
    logs.append(f"Added trusted IP: {name} -> {ip_address}")
    send_notification(f"Trusted IP added: {name} -> {ip_address}")

# Function to allow or disallow traffic from a specific IP
def allow_disallow_ip(src_ip, action):
    if action == "allow":
        trusted_ips[src_ip] = src_ip
        logs.append(f"Allowed traffic from {src_ip}")
        send_notification(f"Traffic allowed from {src_ip}")
    elif action == "disallow":
        if src_ip in trusted_ips:
            del trusted_ips[src_ip]
            logs.append(f"Disallowed traffic from {src_ip}")
            send_notification(f"Traffic disallowed from {src_ip}")

# Function to show allowed and disallowed IPs
def show_allowed_disallowed_ips():
    allowed_ips = [ip for ip in trusted_ips.values()]
    disallowed_ips = [ip for ip in trusted_ips if ip not in allowed_ips]
    return allowed_ips, disallowed_ips

# msfconsole-like terminal interface
def start_console(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(500)

    # Colors setup
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLACK)

    global logs, alerts
    menu_options = [
        "1. Set Trusted IP",
        "2. Allow/Disallow IP",
        "3. Input Ladder Command",
        "4. View Logs",
        "q. Quit"
    ]

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Display application name with larger text
        stdscr.addstr(0, (w // 2) - 8, "HoneyPi_bot", curses.A_BOLD)
        stdscr.addstr(1, (w // 2) - 17, "Real-time Traffic Monitoring", curses.A_BOLD)
        stdscr.addstr(2, (w // 2) - 8, "Author: Sangeevan", curses.A_BOLD)

        # Display Alert if any
        if alerts:
            stdscr.addstr(h // 2 - 2, 0, f"ALERT: {alerts[-1]}", curses.A_BOLD)

        # Display Menu Options
        for idx, option in enumerate(menu_options):
            stdscr.addstr(h // 2 + idx, (w // 2) - len(option) // 2, option, curses.A_BOLD)

        stdscr.addstr(h - 1, 0, "Press 'q' to quit.", curses.A_BOLD)

        key = stdscr.getch()

        if key == ord('q'):
            break
        elif key == ord('1'):
            set_trusted_ip_menu(stdscr)
        elif key == ord('2'):
            allow_disallow_ip_menu(stdscr)
        elif key == ord('3'):
            input_ladder_command_menu(stdscr)
        elif key == ord('4'):
            view_logs_menu(stdscr)

        stdscr.refresh()

# Submenu for Set Trusted IP
def set_trusted_ip_menu(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter IP address to add as trusted:", curses.A_BOLD)
    stdscr.refresh()
    curses.echo()
    ip = stdscr.getstr(1, 0).decode("utf-8")
    stdscr.addstr(2, 0, "Enter name for the trusted IP:", curses.A_BOLD)
    stdscr.refresh()
    name = stdscr.getstr(3, 0).decode("utf-8")
    set_trusted_ip(ip, name)
    curses.noecho()

    # Wait for 'q' to go back to the main menu
    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

# Submenu for Allow/Disallow IP
def allow_disallow_ip_menu(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Allow/Disallow IPs", curses.A_BOLD)
    
    allowed_ips, disallowed_ips = show_allowed_disallowed_ips()

    # Show allowed IPs
    stdscr.addstr(2, 0, "Allowed IPs:", curses.A_BOLD)
    for idx, ip in enumerate(allowed_ips):
        stdscr.addstr(3 + idx, 0, f"Allowed: {ip}")

    # Show disallowed IPs
    stdscr.addstr(2 + len(allowed_ips) + 1, 0, "Disallowed IPs:", curses.A_BOLD)
    for idx, ip in enumerate(disallowed_ips):
        stdscr.addstr(3 + len(allowed_ips) + idx, 0, f"Disallowed: {ip}")

    stdscr.addstr(3 + len(allowed_ips) + len(disallowed_ips) + 1, 0, "Enter IP to change status (allow/disallow):", curses.A_BOLD)
    stdscr.refresh()
    curses.echo()
    ip = stdscr.getstr(3 + len(allowed_ips) + len(disallowed_ips) + 2, 0).decode("utf-8")
    stdscr.addstr(3 + len(allowed_ips) + len(disallowed_ips) + 3, 0, "Enter action (allow/disallow):", curses.A_BOLD)
    stdscr.refresh()
    action = stdscr.getstr(3 + len(allowed_ips) + len(disallowed_ips) + 4, 0).decode("utf-8")
    allow_disallow_ip(ip, action)
    curses.noecho()

    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

# Submenu for Input Ladder Command
def input_ladder_command_menu(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Input Ladder Logic Command:", curses.A_BOLD)
    stdscr.refresh()
    curses.echo()
    ladder_command = stdscr.getstr(1, 0).decode("utf-8")

    stdscr.addstr(2, 0, f"Current Ladder Logic: {ladder_command}")
    curses.noecho()

    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

# Submenu for View Logs
def view_logs_menu(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Logs:", curses.A_BOLD)
    for i, log in enumerate(logs[-10:]):  # Display last 10 logs
        stdscr.addstr(i + 1, 0, log)
    stdscr.refresh()
    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

# Main function to start the app
def main():
    curses.wrapper(start_console)

if __name__ == "__main__":
    main()
