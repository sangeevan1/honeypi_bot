import curses
import logging

# Set up logging to record alerts
logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO)

# Default configuration
trusted_ips = {
    "SCADA": "192.168.90.5",
    "Workstation": "192.168.90.10",
}

plc_ip = "192.168.96.2"
honeypot_ips = [
    "192.168.96.114",
    "192.168.96.115",
]

vulnerable_protocols = {
    "Modbus": [502],
    "S7comm": [102],
    "OPC": [135],
}

logs = []  # In-memory log storage for GUI display

# Function to send notifications
def send_notification(message):
    logging.info(f"Notification: {message}")
    logs.append(f"Notification: {message}")

# Function to set a trusted IP
def set_trusted_ip(ip_address, name):
    trusted_ips[name] = ip_address
    logs.append(f"Added trusted IP: {name} -> {ip_address}")
    send_notification(f"Trusted IP added: {name} -> {ip_address}")

# Function to allow or disallow traffic from a specific IP
def allow_disallow_ip(src_ip, action):
    if action == "allow":
        trusted_ips[src_ip] = src_ip
        logs.append(f"Allowed traffic from {src_ip}")
        send_notification(f"Traffic allowed from {src_ip}")
    elif action == "disallow":
        if src_ip in trusted_ips:
            del trusted_ips[src_ip]
            logs.append(f"Disallowed traffic from {src_ip}")
            send_notification(f"Traffic disallowed from {src_ip}")

# Function to view current iptables rules
def view_current_rules():
    logs.append("Current iptables rules:")
    # Simulate viewing current rules (can be replaced with real iptables check)
    rules = "iptables -t nat -L -n -v"
    logs.append(rules)

# Function to handle ladder command input
def input_ladder_command():
    logs.append("Input ladder command received.")
    send_notification("Ladder command received.")

# Terminal GUI using curses
def gui(stdscr):
    curses.curs_set(0)
    stdscr.nodelay = True
    stdscr.timeout = 500

    # Colors setup
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLACK)

    global logs
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Display application name with larger text
        stdscr.addstr(0, (w // 2) - 8, "HoneyPi_bot", curses.A_BOLD)
        stdscr.addstr(1, (w // 2) - 17, "Real-time Traffic Monitoring", curses.A_BOLD)
        stdscr.addstr(2, (w // 2) - 8, "Author: Sangeevan", curses.A_BOLD)

        # Menu options, displayed centered
        menu = [
            "1. Set Trusted IP",
            "2. View Current Rules",
            "3. Allow/Disallow IP",
            "4. Input Ladder Command",
            "5. View Logs",
            "q. Quit"
        ]
        menu.each_with_index do |option, idx|
            stdscr.addstr(h // 2 + idx - 2, (w // 2) - option.length // 2, option, curses.A_BOLD)
        end

        # Footer
        stdscr.addstr(h - 1, 0, "Press 'q' to quit.", curses.A_BOLD)

        # Handle user input
        key = stdscr.getch()

        case key:
            when 'q'.ord:
                break
            when '1'.ord:
                stdscr.clear()
                stdscr.addstr(0, 0, "Enter IP address to add as trusted:")
                stdscr.refresh()
                curses.echo()
                ip = stdscr.getstr().strip()
                stdscr.addstr(2, 0, "Enter name for the trusted IP:")
                stdscr.refresh()
                name = stdscr.getstr().strip()
                set_trusted_ip(ip, name)
                curses.noecho()
            when '2'.ord:
                view_current_rules()
            when '3'.ord:
                stdscr.clear()
                stdscr.addstr(0, 0, "Enter IP address to allow/disallow:")
                stdscr.refresh()
                curses.echo()
                ip = stdscr.getstr().strip()
                stdscr.addstr(2, 0, "Enter action (allow/disallow):")
                stdscr.refresh()
                action = stdscr.getstr().strip()
                allow_disallow_ip(ip, action)
                curses.noecho()
            when '4'.ord:
                stdscr.clear()
                stdscr.addstr(0, 0, "Input ladder command:")
                stdscr.refresh()
                curses.echo()
                command = stdscr.getstr().strip()
                input_ladder_command()
                curses.noecho()
            when '5'.ord:
                stdscr.clear()
                stdscr.addstr(0, 0, "Viewing logs:")
                logs.last(10).each_with_index do |log, i|
                    stdscr.addstr(i + 1, 0, log)
                end
                stdscr.refresh()
                stdscr.getch()

        stdscr.refresh()
        sleep(0.5)


if __name__ == "__main__":
    curses.wrapper(gui)
