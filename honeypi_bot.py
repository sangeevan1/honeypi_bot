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

# Function to display current iptables rules
def view_current_rules():
    logs.append("Current iptables rules:")
    rules = subprocess.check_output(["sudo", "iptables", "-t", "nat", "-L", "-n", "-v"]).decode("utf-8")
    logs.append(rules)

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
        stdscr.addstr(h - 1, 0, "Press 'q' to exit, '1' to set trusted IP, '2' to view current rules...")

        # Handle user input
        key = stdscr.getch()

        if key == ord('q'):
            break
        elif key == ord('1'):
            stdscr.clear()
            stdscr.addstr(0, 0, "Enter IP address to add as trusted:")
            stdscr.refresh()
            curses.echo()
            ip = stdscr.getstr(1, 0).decode("utf-8")
            stdscr.addstr(2, 0, "Enter name for the trusted IP:")
            stdscr.refresh()
            name = stdscr.getstr(3, 0).decode("utf-8")
            set_trusted_ip(ip, name)
            curses.noecho()
        elif key == ord('2'):
            view_current_rules()
        elif key == ord('3'):
            stdscr.clear()
            stdscr.addstr(0, 0, "Enter IP address to allow/disallow:")
            stdscr.refresh()
            curses.echo()
            ip = stdscr.getstr(1, 0).decode("utf-8")
            stdscr.addstr(2, 0, "Enter action (allow/disallow):")
            stdscr.refresh()
            action = stdscr.getstr(3, 0).decode("utf-8")
            allow_disallow_ip(ip, action)
            curses.noecho()

        stdscr.refresh()
        time.sleep(0.5)

if __name__ == "__main__":
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.start()

    curses.wrapper(gui)
