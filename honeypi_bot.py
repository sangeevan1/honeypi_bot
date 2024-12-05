import os
import time
import threading
from scapy.all import sniff, TCP, IP

# Constants
LOG_FILE = "honeypot_alerts.log"
HONEYPOT_IP = "192.168.96.114"  # Predefined Honeypot IP
SCADA_IP = "192.168.90.5"       # Predefined SCADA IP
PLC_IP = "192.168.96.2"         # Predefined PLC IP
VULNERABLE_PORTS = [80, 502, 102, 135]  # Common attack and vulnerable ports
TRUSTED_IPS = [HONEYPOT_IP, SCADA_IP, PLC_IP]
INTRUSION_KEYWORDS = ["Nmap", "masscan", "zmap", "attack", "scan", "SYN"]

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

        # If the packet is targeting vulnerable ports, raise an alert
        if dst_port in VULNERABLE_PORTS and src_ip not in TRUSTED_IPS:
            alert_message = f"Suspicious traffic detected from {src_ip} to {dst_ip}:{dst_port}"
            log_alert(alert_message)
            redirect_to_honeypot(src_ip)


# Redirect suspicious traffic to the honeypot
def redirect_to_honeypot(src_ip):
    print(f"Redirecting traffic from {src_ip} to honeypot ({HONEYPOT_IP}).")
    log_alert(f"Redirecting traffic from {src_ip} to honeypot.")
    apply_iptables_rules(src_ip, "REDIRECT")


# Apply iptables rules
def apply_iptables_rules(ip, action):
    if action == "REDIRECT":
        # Redirect traffic from the source IP to the honeypot
        command = f"sudo iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}"
    elif action == "REMOVE_REDIRECT":
        # Remove redirection rule
        command = f"sudo iptables -t nat -D PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}"
    else:
        return
    os.system(command)


# Background network monitoring function
def network_monitoring():
    print("\033[0;33mStarting background intrusion detection using Scapy...\033[0m")
    log_alert("Intrusion detection started in the background.")

    try:
        sniff(filter="tcp", prn=analyze_packet, store=0)  # Start sniffing packets
    except KeyboardInterrupt:
        print("\n\033[0;33mStopping network monitoring...\033[0m")
        log_alert("Network monitoring stopped.")
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


# Clear the screen
def clear_screen():
    os.system("clear")


# Exit the application
def exit_application():
    print("Stopping background monitoring and exiting...")
    log_alert("Application exited.")
    time.sleep(1)
    exit()


# Main menu
def main_menu():
    global alert_message

    while True:
        clear_screen()

        # Display any alert message
        if alert_message:
            print(f"\033[0;31mRecent Alert: {alert_message}\033[0m")
            alert_message = ""  # Clear the message after displaying

        print("\033[1;34m--- Honeypot Management Menu ---\033[0m")
        print("1. View Logs")
        print("2. Clear Screen")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            view_logs()
        elif choice == "2":
            clear_screen()
        elif choice == "3":
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
