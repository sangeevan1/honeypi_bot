import os
import time
import subprocess
import re
from colorama import Fore, Style, init

init(autoreset=True)

def main_menu():
    while True:
        print("\n--- HoneyPi-Bot ---")
        print("1. Start SOC: Real-time Analysis (Suricata)")
        print("2. View Logs")
        print("3. Manage IPs (Allow/Block)")
        print("4. Start/Stop Suricata")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            start_soc()
        elif choice == "2":
            view_logs()
        elif choice == "3":
            manage_ips()
        elif choice == "4":
            start_stop_suricata()
        elif choice == "5":
            print("Exiting HoneyPi-Bot. Goodbye!")
            stop_suricata()  # Stop Suricata before exiting
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

def start_soc():
    print("\n--- SOC: Real-time Analysis ---")
    print("Monitoring traffic for malicious or suspicious activities...\n")
    print("Press CTRL+C to return to the main menu.")
    
    try:
        # Tail the Suricata logs for live updates
        log_file = "/var/log/suricata/eve.json"
        if not os.path.exists(log_file):
            print(Fore.RED + "Suricata log file not found! Ensure Suricata is running.")
            return
        
        with open(log_file, "r") as file:
            # Continuously read new log entries
            file.seek(0, os.SEEK_END)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Parse Suricata logs for suspicious or malicious activity
                if "alert" in line:
                    alert = extract_suricata_alert(line)
                    if alert:
                        print(Fore.RED + f"ALERT: {alert}")
                else:
                    print(Style.DIM + line.strip())

    except KeyboardInterrupt:
        print("\nReturning to the main menu.")

def extract_suricata_alert(log_entry):
    # Extract relevant fields from Suricata JSON logs
    try:
        import json
        log = json.loads(log_entry)
        if "alert" in log:
            alert = log["alert"]
            return f"[{alert['severity']}] {alert['signature']} | Source: {log['src_ip']} | Destination: {log['dest_ip']}"
    except Exception as e:
        return None

def view_logs():
    print("\n--- Logs ---")
    log_file = "system_logs.txt"

    if not os.path.exists(log_file):
        print(Fore.RED + "No logs found!")
        return

    print("Date & Time          Event")
    print("-" * 50)

    with open(log_file, "r") as file:
        for line in file:
            print(line.strip())

    input("\nPress Enter to return to the main menu.")

def log_event(event):
    log_file = "system_logs.txt"
    with open(log_file, "a") as file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp} - {event}\n")

def manage_ips():
    print("\n--- Manage IPs ---")
    print("1. Block an IP")
    print("2. Unblock an IP")
    print("3. Return to Main Menu")
    choice = input("Enter your choice: ")

    if choice == "1":
        block_ip()
    elif choice == "2":
        unblock_ip()
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice. Please try again.")

def block_ip():
    ip = input("Enter the IP address to block: ")
    if validate_ip(ip):
        print(f"Blocking IP: {ip}")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        log_event(f"Blocked IP: {ip}")
        print(Fore.GREEN + f"IP {ip} has been blocked.")
    else:
        print(Fore.RED + "Invalid IP address. Please try again.")

def unblock_ip():
    ip = input("Enter the IP address to unblock: ")
    if validate_ip(ip):
        print(f"Unblocking IP: {ip}")
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        log_event(f"Unblocked IP: {ip}")
        print(Fore.GREEN + f"IP {ip} has been unblocked.")
    else:
        print(Fore.RED + "Invalid IP address. Please try again.")

def validate_ip(ip):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(ip))

def start_stop_suricata():
    print("\n--- Suricata Control ---")
    print("1. Start Suricata")
    print("2. Stop Suricata")
    print("3. Return to Main Menu")
    choice = input("Enter your choice: ")

    if choice == "1":
        start_suricata()
    elif choice == "2":
        stop_suricata()
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice. Please try again.")

def start_suricata():
    print(Fore.GREEN + "Starting Suricata...\n")
    # Start Suricata in the background
    process = subprocess.Popen(["sudo", "suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"])
    time.sleep(2)  # Give Suricata some time to start
    print(Fore.GREEN + "Suricata is now running.")

def stop_suricata():
    print(Fore.RED + "Stopping Suricata...\n")
    # Stop Suricata by killing the process
    os.system("sudo pkill suricata")
    print(Fore.GREEN + "Suricata has been stopped.")

if __name__ == "__main__":
    # Automatically start Suricata when the script is run
    start_suricata()

    # Run the main menu
    main_menu()
