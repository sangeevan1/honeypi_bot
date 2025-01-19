import re
import os
import time
import subprocess
from prettytable import PrettyTable
from colorama import Fore, Style, init
from datetime import datetime

# Initialise colorama
init(autoreset=True)

blocked_ips = set()

# Validate IP address format
def validate_ip(ip):
    """Validate IP address format."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)

# Block an IP address
def block_ip(ip):
    """Block an IP address."""
    if ip in blocked_ips:
        print(Fore.YELLOW + f"{ip} is already blocked.")
        return
    print("Blocking IP... Please wait.")
    time.sleep(2)  # Simulate delay
    blocked_ips.add(ip)
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    print(Fore.GREEN + f"{ip} has been blocked.")

# Unblock an IP address
def unblock_ip(ip):
    """Unblock an IP address."""
    if ip not in blocked_ips:
        print(Fore.YELLOW + f"{ip} is not blocked.")
        return
    print("Unblocking IP... Please wait.")
    time.sleep(2)  # Simulate delay
    blocked_ips.remove(ip)
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    print(Fore.GREEN + f"{ip} has been unblocked.")

# Real-time SOC Analysis (simulating log collection from syslog or network monitoring tools)
def show_soc():
    """Simulate SOC analysis and log activity."""
    print(Fore.BLUE + "--- SOC Analysis ---")
    print("Monitoring activities (Press Ctrl+C to stop):")
    try:
        while True:
            log = generate_real_soc_log()
            print(log)
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nReturning to main menu...")

# Generate a real SOC log (this can be replaced with real data collection from syslog, tcpdump, etc.)
def generate_real_soc_log():
    """Simulate generating a real SOC log entry from system logs or network monitoring tools."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Simulate fetching data from logs (replace with actual log fetching)
    log_entry = fetch_real_log_entry()
    
    if "unauthorized" in log_entry.lower():
        event_type = "ALERT"
    else:
        event_type = "INFO"
    
    source_ip, dest_ip, action = log_entry
    return f"{now} | {event_type} | Source: {source_ip} | Destination: {dest_ip} | Action: {action}"

def fetch_real_log_entry():
    """Simulate fetching a real log entry from network tools (syslog, tcpdump, etc.)."""
    # Example of a real log entry - in practice, replace this with actual log parsing
    source_ip = "192.168.95.100"
    dest_ip = "192.168.96.200"
    action = "Unauthorized access attempt detected"
    return source_ip, dest_ip, action

# Display logs in a table format
def show_logs():
    """Display all logs in a table format."""
    print(Fore.BLUE + "--- Log Viewer ---")
    
    # Simulate reading real log files (replace with actual file reading)
    logs = read_real_logs_from_file("/var/log/syslog")
    
    table = PrettyTable(["Time", "Event", "Source", "Destination"])
    for log in logs:
        table.add_row([log["Time"], log["Event"], log["Source"], log["Dest"]])
    
    print(table)
    input("\nPress Enter to return to the main menu...")

def read_real_logs_from_file(log_file_path):
    """Read real logs from a log file (e.g., syslog, or custom SCADA logs)."""
    logs = []
    try:
        with open(log_file_path, "r") as file:
            for line in file.readlines():
                # Simulate extracting relevant info from a real log
                if "unauthorized" in line:
                    logs.append({
                        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "Event": "Unauthorized access attempt",
                        "Source": "192.168.95.100",
                        "Dest": "192.168.96.200",
                    })
    except FileNotFoundError:
        print(Fore.RED + "Log file not found. Please ensure the log file path is correct.")
    return logs

# Simulate detecting suspicious traffic (e.g., port scanning, DDoS attempts, etc.)
def suspicious_traffic_alert():
    """Simulate detecting suspicious traffic."""
    print(Fore.RED + "ALERT: Suspicious traffic detected from 192.168.99.1 to 192.168.96.2")

# IP Blocking Manager (Manual blocking/unblocking)
def ip_blocking_manager():
    """Manage IP blocking and unblocking."""
    while True:
        print(Fore.BLUE + "--- IP Blocking Manager ---")
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(f" - {ip}")
        print("\nOptions:")
        print("1. Block an IP")
        print("2. Unblock an IP")
        print("3. Return to Main Menu")
        choice = input("Enter your choice: ")
        if choice == "1":
            ip = input("Enter IP to block: ")
            if validate_ip(ip):
                block_ip(ip)
            else:
                print(Fore.RED + "Invalid IP format. Try again.")
        elif choice == "2":
            ip = input("Enter IP to unblock: ")
            if validate_ip(ip):
                unblock_ip(ip)
            else:
                print(Fore.RED + "Invalid IP format. Try again.")
        elif choice == "3":
            break
        else:
            print(Fore.RED + "Invalid choice. Try again.")

# Main Menu (choose between SOC analysis, log viewing, or IP blocking)
def main_menu():
    """Display the main menu."""
    while True:
        print(Fore.GREEN + "\n--- HoneyPi-Bot ---")
        print("1. SOC Analysis (Monitor PLC and SCADA)")
        print("2. View Logs")
        print("3. Manage IP Blocking")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            show_soc()
        elif choice == "2":
            show_logs()
        elif choice == "3":
            ip_blocking_manager()
        elif choice == "4":
            print("Exiting HoneyPi-Bot. Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
