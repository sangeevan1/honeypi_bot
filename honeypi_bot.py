import os
import time
import threading
from scapy.all import sniff, TCP, IP, Raw

# Constants
LOG_FILE = "honeypot_alerts.log"
HONEYPOT_IP = "192.168.96.114"  # Predefined Honeypot IP
SCADA_IP = "192.168.90.5"       # Predefined SCADA IP
PLC_IP = "192.168.96.2"         # Predefined PLC IP
VULNERABLE_PORTS = [80, 502, 102, 135]  # Common attack and vulnerable ports
TRUSTED_IPS = [HONEYPOT_IP, SCADA_IP]   # Predefined trusted IPs
ALLOWED_IPS = []                 # Dynamically managed list of allowed IPs
INTRUSION_KEYWORDS = ["Nmap", "masscan", "zmap", "metasploit", "sqlmap", "Hydra", "exploit", "reverse shell", "scan", "SYN"]  # Intrusion detection keywords

# Global Variables
alert_message = ""  # Stores the most recent alert message
monitoring_thread = None  # Background thread for network monitoring

# Function to log alerts to a file
def log_alert(message):
    global alert_message
    alert_message = message  # Set the latest alert message

    with open(LOG_FILE, "a") as log_file:
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime())
        log_file.write(f"{timestamp} {message}\n")

    print(f"\033[0;31mALERT: {message}\033[0m")


# Packet analysis function
def analyze_packet(packet):
    global alert_message

    # Check for TCP packets
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        # If the packet is targeting the PLC and the IP is not allowed, raise an alert
        if dst_ip == PLC_IP and src_ip not in ALLOWED_IPS:
            alert_message = f"Unauthorized access attempt from {src_ip} to PLC on port {dst_port}"
            log_alert(alert_message)
            redirect_to_honeypot(src_ip, "Unauthorized access")

        elif dst_port in VULNERABLE_PORTS and src_ip not in TRUSTED_IPS:
            alert_message = f"Suspicious traffic detected from {src_ip} to {dst_ip}:{dst_port}"
            log_alert(alert_message)
            redirect_to_honeypot(src_ip, "Suspicious traffic")

        # Check for attack tool patterns (e.g., Nmap, masscan, metasploit, sqlmap)
        if any(keyword in str(packet).lower() for keyword in INTRUSION_KEYWORDS):
            alert_message = f"Possible attack detected from {src_ip} (Keyword Match)"
            log_alert(alert_message)
            redirect_to_honeypot(src_ip, "Possible Attack Detected")

        # Detect Metasploit reverse shell traffic (common patterns)
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            # Detect reverse shell attempts (Metasploit often uses specific payloads)
            if "metasploit" in payload.lower() or "reverse shell" in payload.lower():
                alert_message = f"Possible Metasploit reverse shell detected from {src_ip}"
                log_alert(alert_message)
                redirect_to_honeypot(src_ip, "Metasploit Reverse Shell Attempt")


# Redirect suspicious traffic to the honeypot
def redirect_to_honeypot(src_ip, reason):
    print(f"Redirecting traffic from {src_ip} to honeypot ({HONEYPOT_IP}) due to {reason}.")
    log_alert(f"Redirecting traffic from {src_ip} to honeypot due to {reason}.")
    apply_iptables_rules(src_ip, "REDIRECT")


# Apply iptables rules
def apply_iptables_rules(ip, action):
    if action == "REDIRECT":
        # Redirect traffic from the source IP to the honeypot
        command = f"sudo iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}"
    elif action == "REMOVE_REDIRECT":
        # Remove redirection rule
        command = f"sudo iptables -t nat -D PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}"
    elif action == "ALLOW":
        command = f"sudo iptables -A INPUT -s {ip} -j ACCEPT"
    elif action == "DISALLOW":
        command = f"sudo iptables -D INPUT -s {ip} -j ACCEPT"
    else:
        return
    os.system(command)


# Add or remove IPs from the allowed list
def manage_allowed_ips():
    print("\033[1;34m--- Manage Allowed IPs ---\033[0m")
    action = input("Enter action (allow/disallow): ").strip().lower()
    ip = input("Enter the IP address: ").strip()

    if action == "allow":
        if ip not in ALLOWED_IPS:
            ALLOWED_IPS.append(ip)
            apply_iptables_rules(ip, "ALLOW")
            print(f"IP {ip} has been allowed.")
        else:
            print(f"IP {ip} is already in the allowed list.")
    elif action == "disallow":
        if ip in ALLOWED_IPS:
            ALLOWED_IPS.remove(ip)
            apply_iptables_rules(ip, "DISALLOW")
            print(f"IP {ip} has been disallowed.")
        else:
            print(f"IP {ip} is not in the allowed list.")
    else:
        print("Invalid action. Please choose 'allow' or 'disallow'.")
    input("Press Enter to return to the main menu...")


# Display the allowed and disallowed IPs in table format
def view_allowed_ips():
    print("\033[1;34m--- Allowed IPs ---\033[0m")
    print("\033[1;32mIP Address \t\t Status\033[0m")
    for ip in ALLOWED_IPS:
        print(f"{ip} \t\t Allowed")
    print("\nPress Enter to return to the main menu...")


# View live traffic
def view_live_traffic():
    print("\033[1;34m--- Live Traffic ---\033[0m")
    try:
        sniff(filter="tcp", prn=live_traffic_view, count=10, store=0)
    except KeyboardInterrupt:
        print("\nReturning to main menu...")
    except Exception as e:
        print(f"Error: {e}")
    input("Press Enter to return to the main menu...")


# Live traffic view with color coding
def live_traffic_view(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport

        # Display honeypot traffic in yellow
        if dst_ip == HONEYPOT_IP:
            print(f"\033[1;33mHoneypot traffic from {src_ip} detected!\033[0m")

        # Vulnerable traffic (even from allowed IPs) in red to PLC
        if dst_ip == PLC_IP and dst_port in VULNERABLE_PORTS:
            print(f"\033[0;31mVulnerable traffic from {src_ip} detected to PLC on port {dst_port}\033[0m")


# Background network monitoring function
def network_monitoring():
    print("\033[0;33mStarting background intrusion detection...\033[0m")
    log_alert("Intrusion detection started in the background.")

    try:
        sniff(filter="tcp", prn=analyze_packet, store=0)  # Start sniffing packets
    except Exception as e:
        log_alert(f"Error in network monitoring: {e}")


# Display logs
def view_logs():
    print("\033[1;34m--- Log File ---\033[0m")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log_file:
            print(log_file.read())
    else:
        print("No logs found.")
    input("Press Enter to return to the main menu...")


# Main menu function
def main_menu():
    global alert_message
    while True:
        os.system("clear")  # Clear screen
        print("\033[1;36m" + "=" * 40 + "\033[0m")
        print("\033[1;32mHoneypot Monitor \033[0m".center(40))
        print("\033[1;36m" + "=" * 40 + "\033[0m\n")

        # Display any alert message
        if alert_message:
            print(f"\033[0;31mRecent Alert: {alert_message}\033[0m")
            alert_message = ""  # Clear the message after displaying

        print("\033[1;34m--- Main Menu ---\033[0m")
        print("1. View Logs")
        print("2. Manage Allowed IPs")
        print("3. View Allowed IPs in Table")
        print("4. View Live Traffic")
        print("5. Clear Screen")
        print("6. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            view_logs()
        elif choice == "2":
            manage_allowed_ips()
        elif choice == "3":
            view_allowed_ips()
        elif choice == "4":
            view_live_traffic()
        elif choice == "5":
            clear_screen()
        elif choice == "6":
            exit_application()
        else:
            print("Invalid choice. Please try again.")
            time.sleep(1)


# Start the background monitoring thread
def start_monitoring():
    global monitoring_thread
    monitoring_thread = threading.Thread(target=network_monitoring, daemon=True)
    monitoring_thread.start()


if __name__ == "__main__":
    # Ensure Scapy runs with root privileges
    if os.geteuid() != 0:
        print("This script must be run as root. Please use sudo.")
        exit(1)

    # Start background network monitoring
    start_monitoring()

    # Launch the main menu
    main_menu()
