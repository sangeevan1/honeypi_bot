import os
import time
import json
from datetime import datetime
from colorama import Fore, Style, init
from prettytable import PrettyTable

# Initialize colorama for colored output
init(autoreset=True)

# File paths for logs
PLC_LOGS = "plc_logs.json"
HONEYPOT_LOGS = "honeypot_logs.json"
DIVERTED_IPS_LOGS = "diverted_ips.json"

# Honeypot IP Address
HONEYPOT_IP = "192.168.96.114"

# Suricata log file location
SURICATA_LOG_FILE = "/var/log/suricata/eve.json"

def write_log(file, log_data):
    """Write log data to a file in JSON format."""
    with open(file, "a") as f:
        f.write(json.dumps(log_data) + "\n")

def read_logs(file):
    """Read logs from a file and return as a list."""
    if os.path.exists(file):
        with open(file, "r") as f:
            return [json.loads(line.strip()) for line in f]
    return []

def start_suricata():
    """Start Suricata for real-time monitoring."""
    print(Fore.GREEN + "Starting Suricata...")
    os.system("sudo suricata -c /etc/suricata/suricata.yaml -i eth0 &")
    print(Fore.GREEN + "Suricata is running.")

def monitor_traffic():
    """Monitor PLC traffic and show in a table format, diverting malicious activity."""
    if not os.path.exists(SURICATA_LOG_FILE):
        print(Fore.RED + "Suricata log file not found! Ensure Suricata is running.")
        return

    print(Fore.GREEN + "Monitoring traffic... Press CTRL+C to stop.")
    table = PrettyTable(["Timestamp", "Source IP", "Destination IP", "Alert"])

    try:
        with open(SURICATA_LOG_FILE, "r") as file:
            file.seek(0, os.SEEK_END)  # Start at the end of the log file
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    log = json.loads(line)
                    if "alert" in log:
                        alert = log["alert"]
                        src_ip = log.get("src_ip", "Unknown")
                        dest_ip = log.get("dest_ip", "Unknown")
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        # Add to table and display
                        table.add_row([timestamp, src_ip, dest_ip, alert["signature"]])
                        os.system("clear")
                        print(Fore.GREEN + table.get_string(title="PLC Traffic"))

                        # Redirect malicious traffic to honeypot
                        if is_malicious(src_ip):
                            redirect_to_honeypot(src_ip)
                            save_diverted_ip(src_ip)
                except json.JSONDecodeError:
                    continue
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nStopped traffic monitoring.")

def is_malicious(ip):
    """Determine if an IP is malicious (basic logic; replace with actual checks)."""
    # Add logic to detect malicious IPs (e.g., based on known threat intelligence)
    return True  # Placeholder: All alerts are considered malicious

def redirect_to_honeypot(ip):
    """Redirect malicious traffic to honeypot."""
    print(Fore.YELLOW + f"Redirecting IP {ip} to honeypot...")
    os.system(f"sudo iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}")
    log_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "action": "Redirected to honeypot"
    }
    write_log(DIVERTED_IPS_LOGS, log_data)
    print(Fore.GREEN + f"IP {ip} successfully redirected.")

def save_diverted_ip(ip):
    """Save diverted IPs for later analysis."""
    diverted_ips = read_logs(DIVERTED_IPS_LOGS)
    if ip not in [entry["ip"] for entry in diverted_ips]:
        write_log(DIVERTED_IPS_LOGS, {"ip": ip, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

def manage_ips():
    """Manage IP blocking and unblocking."""
    while True:
        print("\n--- Manage IPs ---")
        print("1. Block IP")
        print("2. Allow IP")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            ip = input("Enter IP to block: ")
            if validate_ip(ip):
                os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                print(Fore.RED + f"IP {ip} blocked.")
            else:
                print(Fore.RED + "Invalid IP format.")
        elif choice == "2":
            ip = input("Enter IP to allow: ")
            if validate_ip(ip):
                os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
                print(Fore.GREEN + f"IP {ip} allowed.")
            else:
                print(Fore.RED + "Invalid IP format.")
        elif choice == "3":
            break
        else:
            print(Fore.RED + "Invalid choice.")

def validate_ip(ip):
    """Validate the format of an IP address."""
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False

def view_logs():
    """View system logs."""
    while True:
        print("\n--- View Logs ---")
        print("1. PLC Logs")
        print("2. Honeypot Logs")
        print("3. Diverted IPs")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            display_logs(PLC_LOGS)
        elif choice == "2":
            display_logs(HONEYPOT_LOGS)
        elif choice == "3":
            display_logs(DIVERTED_IPS_LOGS)
        elif choice == "4":
            break
        else:
            print(Fore.RED + "Invalid choice.")

def display_logs(file):
    """Display logs from a file."""
    logs = read_logs(file)
    if logs:
        for log in logs:
            print(json.dumps(log, indent=2))
    else:
        print(Fore.RED + "No logs available.")

def main():
    """Main menu for the SOC system."""
    start_suricata()
    while True:
        print("\n--- SOC System ---")
        print("1. SOC: Monitor Traffic to PLC")
        print("2. Manage IPs (Block/Allow)")
        print("3. View Logs")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            monitor_traffic()
        elif choice == "2":
            manage_ips()
        elif choice == "3":
            view_logs()
        elif choice == "4":
            print(Fore.YELLOW + "Exiting SOC system...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
