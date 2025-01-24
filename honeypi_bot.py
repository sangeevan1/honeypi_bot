import os
import time
import json
from datetime import datetime
from prettytable import PrettyTable
from colorama import Fore, Style, init

# Initialize Colorama for colored output
init(autoreset=True)

# Log file paths
PLC_LOGS = "plc_logs.json"
HONEYPOT_LOGS = "honeypot_logs.json"

# Honeypot IP Address
HONEYPOT_IP = "192.168.96.114"

# Suricata log file location
SURICATA_LOG_FILE = "/var/log/suricata/eve.json"

def write_log(file, log_data):
    """Write log data to a JSON file."""
    with open(file, "a") as f:
        f.write(json.dumps(log_data) + "\n")

def start_suricata():
    """Start Suricata with the configuration file."""
    print(Fore.GREEN + "Starting Suricata...")
    os.system("sudo suricata -c /etc/suricata/suricata.yaml -i eth0 &")
    print(Fore.GREEN + "Suricata is running.")

def monitor_traffic():
    """Monitor traffic to detect threats and redirect malicious IPs."""
    if not os.path.exists(SURICATA_LOG_FILE):
        print(Fore.RED + "Suricata log file not found! Ensure Suricata is running.")
        return

    print(Fore.GREEN + "Monitoring traffic... Press CTRL+C to stop.")
    with open(SURICATA_LOG_FILE, "r") as file:
        file.seek(0, os.SEEK_END)  # Start at the end of the log file
        try:
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                try:
                    log = json.loads(line)
                    if "alert" in log:
                        handle_malicious_activity(log)
                except json.JSONDecodeError:
                    continue
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nStopped traffic monitoring.")

def handle_malicious_activity(log):
    """Handle malicious activity detected by Suricata."""
    alert = log["alert"]
    src_ip = log.get("src_ip", "Unknown")
    dest_ip = log.get("dest_ip", "Unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Display alert details
    print(Fore.RED + f"[{timestamp}] ALERT: {alert['signature']}")
    print(Fore.RED + f"Source IP: {src_ip}, Destination IP: {dest_ip}")
    
    # Log the activity
    log_data = {
        "timestamp": timestamp,
        "alert": alert,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "details": "Malicious activity detected"
    }
    write_log(PLC_LOGS, log_data)

    # Redirect malicious traffic to honeypot
    redirect_to_honeypot(src_ip)

def redirect_to_honeypot(ip):
    """Redirect malicious traffic to the honeypot."""
    print(Fore.YELLOW + f"Redirecting IP {ip} to honeypot...")
    os.system(f"sudo iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}")
    honeypot_log = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip,
        "action": "Redirected to honeypot"
    }
    write_log(HONEYPOT_LOGS, honeypot_log)
    print(Fore.GREEN + f"IP {ip} successfully redirected.")

def manage_ips():
    """Block or unblock IP addresses."""
    print("\nIP Management")
    print("1. Block IP")
    print("2. Unblock IP")
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
        ip = input("Enter IP to unblock: ")
        if validate_ip(ip):
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            print(Fore.GREEN + f"IP {ip} unblocked.")
        else:
            print(Fore.RED + "Invalid IP format.")
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice.")

def validate_ip(ip):
    """Validate the format of an IP address."""
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False

def view_logs():
    """View saved logs."""
    print("\nLog Viewer")
    print("1. View PLC Logs")
    print("2. View Honeypot Logs")
    print("3. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        print(Fore.GREEN + "PLC Logs:")
        display_logs(PLC_LOGS)
    elif choice == "2":
        print(Fore.GREEN + "Honeypot Logs:")
        display_logs(HONEYPOT_LOGS)
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice.")

def display_logs(file):
    """Display logs from a specified file."""
    if not os.path.exists(file):
        print(Fore.RED + "No logs available.")
        return

    with open(file, "r") as f:
        for line in f:
            log = json.loads(line.strip())
            print(json.dumps(log, indent=2))

def track_honeypot():
    """Track traffic redirected to the honeypot."""
    print(Fore.GREEN + "Honeypot Traffic:")
    display_logs(HONEYPOT_LOGS)

def main():
    """Main function to run the SOC."""
    start_suricata()
    while True:
        print("\n--- SOC Menu ---")
        print("1. Monitor Traffic (PLC)")
        print("2. Manage IPs (Block/Unblock)")
        print("3. View Logs")
        print("4. Track Honeypot Traffic")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            monitor_traffic()
        elif choice == "2":
            manage_ips()
        elif choice == "3":
            view_logs()
        elif choice == "4":
            track_honeypot()
        elif choice == "5":
            print(Fore.YELLOW + "Exiting SOC...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
