import time
import random
from prettytable import PrettyTable
from colorama import Fore, Style, init
from datetime import datetime
import re
import subprocess

# Initialise colorama
init(autoreset=True)

blocked_ips = set()

def validate_ip(ip):
    """Validate IP address format."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)

def block_ip(ip):
    """Block an IP address."""
    if ip in blocked_ips:
        print(Fore.YELLOW + f"{ip} is already blocked.")
        return
    print("Blocking IP... Please wait.")
    time.sleep(2)  # Simulate delay
    blocked_ips.add(ip)
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(Fore.GREEN + f"{ip} has been blocked.")

def unblock_ip(ip):
    """Unblock an IP address."""
    if ip not in blocked_ips:
        print(Fore.YELLOW + f"{ip} is not blocked.")
        return
    print("Unblocking IP... Please wait.")
    time.sleep(2)  # Simulate delay
    blocked_ips.remove(ip)
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(Fore.GREEN + f"{ip} has been unblocked.")

def generate_live_log():
    """Generate a simulated log entry."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_ip = f"192.168.{random.randint(0, 99)}.{random.randint(1, 255)}"
    dest_ip = f"192.168.96.{random.randint(1, 255)}"
    event_types = ["INFO", "WARNING", "ALERT"]
    actions = [
        "SCADA sent START command to PLC.",
        "SCADA sent STOP command to PLC.",
        "PLC responded with ACK.",
        "Unauthorised command received.",
        "Port scanning detected.",
        "Data exfiltration attempt detected.",
    ]
    event_type = random.choice(event_types)
    action = random.choice(actions)
    suspicious = "Unauthorised" in action or "scanning" in action or "exfiltration" in action
    return {
        "time": now,
        "event_type": event_type,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "action": action,
        "suspicious": suspicious,
    }

def show_soc():
    """Real-time SOC analysis."""
    print(Fore.BLUE + "--- SOC Analysis ---")
    print("Monitoring activities (Press Ctrl+C to stop):")

    table = PrettyTable(["Time", "Event Type", "Source", "Destination", "Action"])
    table.align = "l"
    try:
        while True:
            log = generate_live_log()
            if log["suspicious"]:  # Only show suspicious logs
                table.clear_rows()
                row_colour = Fore.RED if log["suspicious"] else Fore.WHITE
                table.add_row([log["time"], log["event_type"], log["source_ip"], log["dest_ip"], log["action"]])
                print(row_colour + table.get_string())
                print(Fore.RED + f"ALERT: Suspicious activity detected - {log['action']}")
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nStopping SOC analysis and returning to main menu...")

def show_logs():
    """Display historical logs in a table format."""
    print(Fore.BLUE + "--- Log Viewer ---")
    logs = [
        {"Time": "2025-01-19 12:00:00", "Event": "SCADA sent START", "Source": "192.168.95.1", "Dest": "192.168.96.1"},
        {"Time": "2025-01-19 12:01:00", "Event": "PLC responded ACK", "Source": "192.168.96.1", "Dest": "192.168.95.1"},
        {"Time": "2025-01-19 12:02:00", "Event": "Port scanning detected", "Source": "192.168.99.1", "Dest": "192.168.96.1"},
    ]
    table = PrettyTable(["Time", "Event", "Source", "Destination"])
    for log in logs:
        table.add_row([log["Time"], log["Event"], log["Source"], log["Dest"]])
    print(table)
    input("\nPress Enter to return to the main menu...")

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

def main_menu():
    """Display the main menu."""
    while True:
        print(Fore.GREEN + "\n--- HoneyPi-Bot ---")
        print("1. SOC Analysis (Real-Time)")
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
