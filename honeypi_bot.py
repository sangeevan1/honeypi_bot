import subprocess
import time
import re
from prettytable import PrettyTable
from colorama import Fore, init

# Initialise colorama for coloured output
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

def analyze_packet(packet):
    """Analyze the packet for potential incidents."""
    suspicious = False
    incident = ""

    # Basic checks for suspicious patterns (can be expanded further)
    if "ICMP" in packet:
        suspicious = True
        incident = "Potential Ping Flood (ICMP) detected."

    # Port scanning detection: Look for multiple connection attempts from the same source IP
    if "SYN" in packet and "Connection Request" in packet:
        suspicious = True
        incident = "Potential Port Scanning detected."

    # Further incident detection rules can be added here

    return suspicious, incident

def monitor_traffic():
    """Monitor real-time network traffic and print live incidents."""
    print(Fore.BLUE + "--- Real-Time SOC Analysis ---")
    print("Monitoring network traffic... (Press Ctrl+C to stop)")

    table = PrettyTable(["Time", "Source IP", "Destination IP", "Protocol", "Incident"])

    # Start capturing traffic using tcpdump (adjust interface as needed)
    process = subprocess.Popen(
        ["sudo", "tcpdump", "-i", "eth0", "-n", "-v", "tcp", "icmp"],  # Change 'eth0' as necessary
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    try:
        while True:
            # Read each line of output from tcpdump
            packet = process.stdout.readline()

            if packet == '' and process.poll() is not None:
                break
            if packet:
                # Extract relevant information from the packet (source/destination IP, protocol, etc.)
                match = re.search(r'IP (\S+) > (\S+): (\S+)', packet)
                if match:
                    source_ip = match.group(1)
                    dest_ip = match.group(2)
                    protocol = match.group(3)
                    
                    # Analyze the packet for incidents
                    suspicious, incident = analyze_packet(packet)

                    # If suspicious activity is detected, print it
                    if suspicious:
                        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
                        table.add_row([current_time, source_ip, dest_ip, protocol, incident])
                        print(Fore.RED + table.get_string())
                        print(Fore.RED + f"ALERT: {incident}")
            
            time.sleep(1)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nStopping SOC analysis and returning to main menu...")
        process.kill()

def show_logs():
    """Display historical logs in a table format."""
    print(Fore.BLUE + "--- Log Viewer ---")
  
    # Assuming you want to show logs from a saved file or another source. Modify accordingly.
    table = PrettyTable(["Time", "Event", "Source", "Destination"])
    for log in logs:  # Assuming logs is defined elsewhere as a list of dicts
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
            monitor_traffic()
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
