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
PERMITTED_IPS_FILE = "permitted_ips.json"

# Honeypot IP Address
HONEYPOT_IP = "192.168.96.114"

# Suricata log file location
SURICATA_LOG_FILE = "/var/log/suricata/eve.json"

# SCADA IP Address (default empty; user must set it)
SCADA_IP = None

# Set of permitted IPs (SCADA & other trusted sources)
PERMITTED_IPS = set()

# Track processed alerts to avoid duplicates
processed_alerts = {}

# Load permitted IPs from file
def load_permitted_ips():
    global SCADA_IP, PERMITTED_IPS
    if os.path.exists(PERMITTED_IPS_FILE):
        with open(PERMITTED_IPS_FILE, "r") as f:
            data = json.load(f)
            SCADA_IP = data.get("scada_ip", None)
            PERMITTED_IPS.update(data.get("permitted_ips", []))

# Save permitted IPs to file
def save_permitted_ips():
    data = {
        "scada_ip": SCADA_IP,
        "permitted_ips": list(PERMITTED_IPS)
    }
    with open(PERMITTED_IPS_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Write logs to JSON file
def write_log(file, log_data):
    with open(file, "a") as f:
        f.write(json.dumps(log_data) + "\n")

# Start Suricata IDS
def start_suricata():
    print(Fore.GREEN + "Starting Suricata...")
    os.system("sudo suricata -c /etc/suricata/suricata.yaml -i eth0 &")
    print(Fore.GREEN + "Suricata is running.")

# Monitor traffic for threats
def monitor_traffic():
    if not os.path.exists(SURICATA_LOG_FILE):
        print(Fore.RED + "Suricata log file not found! Ensure Suricata is running.")
        return

    print(Fore.GREEN + "Monitoring traffic... Press CTRL+C to stop.")
    with open(SURICATA_LOG_FILE, "r") as file:
        file.seek(0, os.SEEK_END)
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

# Handle malicious activity
def handle_malicious_activity(log):
    global SCADA_IP
    alert = log["alert"]
    src_ip = log.get("src_ip", "Unknown")
    dest_ip = log.get("dest_ip", "Unknown")
    timestamp = datetime.now()
    
    # Skip alert if the IP is SCADA or a permitted IP
    if src_ip == SCADA_IP or src_ip in PERMITTED_IPS:
        if src_ip not in processed_alerts:
            print(Fore.YELLOW + f"⚠️ Skipping alert: {src_ip} is SCADA or a permitted IP.")
        processed_alerts[src_ip] = timestamp
        return

    # Create unique alert key
    alert_key = f"{alert['signature']}-{src_ip}"
    
    # Avoid duplicate alerts within 60 seconds
    if alert_key in processed_alerts and (timestamp - processed_alerts[alert_key]).total_seconds() < 60:
        return

    attack_type = analyze_attack(alert)
    raw_packet = log.get("packet", "No packet data available")

    # Display alert
    print(Fore.RED + f"\n🚨 [{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] **ALERT: {alert['signature']}**")
    print(Fore.RED + f"🛑 **Attack Type:** {attack_type}")
    print(Fore.RED + f"🌐 **Source IP:** {src_ip}  ➡️  **Destination IP:** {dest_ip}")
    print(Fore.RED + f"📜 **Raw Packet Data:**\n{raw_packet}\n")

    # Log alert
    log_data = {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "alert": alert,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "attack_type": attack_type,
        "packet_data": raw_packet,
        "details": "Malicious activity detected"
    }
    write_log(PLC_LOGS, log_data)

    # Redirect traffic to honeypot
    redirect_to_honeypot(src_ip)

    # Update processed alerts
    processed_alerts[alert_key] = timestamp

# Analyze attack type
def analyze_attack(alert):
    signature = alert.get("signature", "").lower()
    
    known_attacks = {
        "nmap": "Network Scan (Nmap)",
        "modbus": "Modbus Exploit Attempt",
        "bruteforce": "Brute Force Attack",
        "port scan": "Port Scanning",
        "sqlmap": "SQL Injection Attack",
        "metasploit": "Metasploit Exploit",
        "nikto": "Web Server Vulnerability Scan",
        "ctmodbus": "Modbus Protocol Exploit"
    }
    
    for key, attack_name in known_attacks.items():
        if key in signature:
            return attack_name
    
    return "Unknown Threat"

# Redirect malicious traffic
def redirect_to_honeypot(ip):
    if ip == SCADA_IP or ip in PERMITTED_IPS:
        return

    print(Fore.YELLOW + f"🔄 Redirecting IP {ip} to honeypot...")
    os.system(f"sudo iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination {HONEYPOT_IP}")
    
    honeypot_log = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip,
        "action": "Redirected to honeypot"
    }
    write_log(HONEYPOT_LOGS, honeypot_log)

# Manage SCADA & Permitted IPs
def manage_ips():
    global SCADA_IP
    load_permitted_ips()

    while True:
        print("\n🔹 **IP Management Menu** 🔹")
        print("1. View SCADA & Permitted IPs")
        print("2. Set SCADA IP")
        print("3. Add Permitted IP")
        print("4. Remove Permitted IP")
        print("5. Exit")
        
        choice = input("Enter your choice: ")

        if choice == "1":
            print(Fore.CYAN + "\n📌 **Current IPs Configuration:**")
            print(Fore.YELLOW + f"SCADA IP: {SCADA_IP if SCADA_IP else 'Not Set'}")
            print(Fore.GREEN + "Permitted IPs: " + (", ".join(PERMITTED_IPS) if PERMITTED_IPS else "No Permitted IPs"))

        elif choice == "2":
            SCADA_IP = input("Enter SCADA IP: ").strip()
            save_permitted_ips()
            print(Fore.GREEN + "✅ SCADA IP set successfully.")

        elif choice == "3":
            ip = input("Enter permitted IP: ").strip()
            if ip:
                PERMITTED_IPS.add(ip)
                save_permitted_ips()
                print(Fore.GREEN + f"✅ IP {ip} added to permitted list.")

        elif choice == "4":
            ip = input("Enter IP to remove: ").strip()
            if ip in PERMITTED_IPS:
                PERMITTED_IPS.discard(ip)
                save_permitted_ips()
                print(Fore.RED + f"🚨 IP {ip} removed from permitted list.")

        elif choice == "5":
            break

# Main function
def main():
    start_suricata()
    while True:
        print("\n--- SOC Menu ---")
        print("1. Monitor Traffic")
        print("2. Manage IPs")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            monitor_traffic()
        elif choice == "2":
            manage_ips()
        elif choice == "3":
            break

if __name__ == "__main__":
    main()
