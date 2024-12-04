#!/bin/bash

# Logging file for alerts
LOG_FILE="honeypot_alerts.log"

# List of trusted IPs (initially empty)
declare -A trusted_ips

# Honeypot IPs (example)
HONEYPOT_IPS=("192.168.96.114" "192.168.96.115")

# Vulnerable ports (for simplicity, we are using just one protocol here)
declare -A vulnerable_ports
vulnerable_ports=( ["Modbus"]=502 ["S7comm"]=102 ["OPC"]=135 )

# Function to log alerts
log_alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> $LOG_FILE
    echo "$message"
}

# Function to detect vulnerable traffic
detect_vulnerable_traffic() {
    # Use tcpdump to sniff packets for vulnerable ports
    sudo tcpdump -i eth0 -nn -v 'tcp port 502 or tcp port 102 or tcp port 135' | while read line; do
        if [[ $line =~ "IP" ]]; then
            log_alert "Vulnerable traffic detected: $line"
            echo -e "\033[0;31mALERT: Vulnerable traffic detected: $line\033[0m"
        fi
    done
}

# Function to detect scanning behavior (e.g., Nmap)
detect_scanning() {
    # Using tcpdump to detect SYN scan (Nmap)
    sudo tcpdump -i eth0 -nn -v 'tcp[tcpflags] == tcp-syn' | while read line; do
        if [[ $line =~ "IP" ]]; then
            log_alert "Possible Nmap scan detected: $line"
            echo -e "\033[0;31mALERT: Possible Nmap scan detected: $line\033[0m"
        fi
    done
}

# Function to set trusted IPs
set_trusted_ip() {
    echo "Enter trusted IP address:"
    read ip_address
    echo "Enter description for this IP:"
    read description
    trusted_ips[$ip_address]=$description
    log_alert "Trusted IP added: $ip_address -> $description"
}

# Function to display trusted IPs
display_trusted_ips() {
    echo -e "\033[1;34m--- Trusted IPs ---\033[0m"
    for ip in "${!trusted_ips[@]}"; do
        echo "$ip -> ${trusted_ips[$ip]}"
    done
}

# Function to allow or disallow an IP
allow_disallow_ip() {
    echo "Enter the IP to allow/disallow:"
    read ip_address
    echo "Enter action (allow/disallow):"
    read action

    if [ "$action" == "allow" ]; then
        trusted_ips[$ip_address]="Allowed"
        iptables -A INPUT -s $ip_address -j ACCEPT
        log_alert "Allowed traffic from IP: $ip_address"
    elif [ "$action" == "disallow" ]; then
        unset trusted_ips[$ip_address]
        iptables -A INPUT -s $ip_address -j DROP
        log_alert "Disallowed traffic from IP: $ip_address"
    else
        echo "Invalid action. Please use 'allow' or 'disallow'."
    fi
}

# Function to view logs
view_logs() {
    echo -e "\033[1;34m--- Logs ---\033[0m"
    cat $LOG_FILE
}

# Main interactive menu
main_menu() {
    while true; do
        clear
        echo -e "\033[1;34m=== HoneyPi - Honeypot Monitor ===\033[0m"
        echo "1. Set Trusted IP"
        echo "2. View Trusted IPs"
        echo "3. Allow/Disallow IP"
        echo "4. View Logs"
        echo "5. Start Traffic Monitoring"
        echo "6. Exit"
        
        read -p "Enter your choice: " choice

        case $choice in
            1)
                set_trusted_ip
                ;;
            2)
                display_trusted_ips
                read -p "Press Enter to return to menu..."
                ;;
            3)
                allow_disallow_ip
                ;;
            4)
                view_logs
                read -p "Press Enter to return to menu..."
                ;;
            5)
                start_monitoring
                ;;
            6)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid choice, try again."
                ;;
        esac
    done
}

# Function to start monitoring
start_monitoring() {
    echo "Starting traffic monitoring..."
    # Run both scanning detection and vulnerable traffic detection in the background
    detect_scanning &
    detect_vulnerable_traffic &
    wait
}

# Run the main menu
main_menu
