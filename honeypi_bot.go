package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	trustedIPs = map[string]string{
		"SCADA":      "192.168.90.5",
		"Workstation": "192.168.90.10",
	}
	plcIP          = "192.168.96.2"
	honeypotIPs    = []string{"192.168.96.114", "192.168.96.115"}
	vulnerablePorts = map[string][]int{
		"Modbus": {502},
		"S7comm": {102},
		"OPC":    {135},
	}
	logs []string
)

func main() {
	// Start packet sniffing
	go startSniffing()

	// Start the interactive menu
	startMenu()
}

func startMenu() {
	for {
		clearScreen()
		printMenu()

		var choice string
		fmt.Print("Enter choice: ")
		fmt.Scanln(&choice)

		switch choice {
		case "1":
			setTrustedIP()
		case "2":
			viewLogs()
		case "3":
			allowDisallowIP()
		case "q":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
			time.Sleep(2 * time.Second)
		}
	}
}

func printMenu() {
	fmt.Println("HoneyPi - Traffic Monitor")
	fmt.Println("1. Set Trusted IP")
	fmt.Println("2. View Logs")
	fmt.Println("3. Allow/Disallow IP")
	fmt.Println("q. Quit")
}

func clearScreen() {
	// Clear terminal screen
	fmt.Print("\033[H\033[2J")
}

func setTrustedIP() {
	var name, ip string
	fmt.Print("Enter name for the trusted IP: ")
	fmt.Scanln(&name)
	fmt.Print("Enter the trusted IP address: ")
	fmt.Scanln(&ip)

	if !isValidIP(ip) {
		fmt.Println("Invalid IP address. Returning to menu...")
		time.Sleep(2 * time.Second)
		return
	}

	trustedIPs[name] = ip
	logs = append(logs, fmt.Sprintf("Added trusted IP: %s -> %s", name, ip))
	fmt.Println("Trusted IP added successfully!")
	time.Sleep(2 * time.Second)
}

func viewLogs() {
	fmt.Println("Logs:")
	for _, logMsg := range logs {
		fmt.Println(logMsg)
	}
	fmt.Println("Press Enter to return to the menu.")
	fmt.Scanln()
}

func allowDisallowIP() {
	var ip, action string
	fmt.Print("Enter IP address to allow or disallow: ")
	fmt.Scanln(&ip)
	fmt.Print("Enter action (allow/disallow): ")
	fmt.Scanln(&action)

	if action != "allow" && action != "disallow" {
		fmt.Println("Invalid action. Returning to menu...")
		time.Sleep(2 * time.Second)
		return
	}

	if action == "allow" {
		trustedIPs[ip] = ip
		logs = append(logs, fmt.Sprintf("Allowed traffic from %s", ip))
	} else {
		delete(trustedIPs, ip)
		logs = append(logs, fmt.Sprintf("Disallowed traffic from %s", ip))
	}

	fmt.Println("Action completed successfully!")
	time.Sleep(2 * time.Second)
}

func isValidIP(ip string) bool {
	re := regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	return re.MatchString(ip)
}

func startSniffing() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening pcap handle:", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		go packetHandler(packet)
	}
}

func packetHandler(packet gopacket.Packet) {
	ipLayer := packet.Layer(gopacket.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*gopacket.layers.IPv4)
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	// Handle traffic from trusted IPs
	if _, exists := trustedIPs[srcIP]; exists {
		logs = append(logs, fmt.Sprintf("Traffic from trusted IP: %s -> %s", srcIP, dstIP))
		return
	}

	// Check for vulnerable traffic
	checkVulnerableTraffic(srcIP, dstIP, packet)

	// Handle potential attack scenarios
	detectScan(srcIP, dstIP, packet)
}

func checkVulnerableTraffic(srcIP, dstIP string, packet gopacket.Packet) {
	tcpLayer := packet.Layer(gopacket.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*gopacket.layers.TCP)
		for protocol, ports := range vulnerablePorts {
			for _, port := range ports {
				if tcp.DstPort == gopacket.LayerType(port) {
					logs = append(logs, fmt.Sprintf("Vulnerable traffic detected: %s -> %s (%s)", srcIP, dstIP, protocol))
					fmt.Println("ALERT: Vulnerable traffic detected!")
					return
				}
			}
		}
	}
}

func detectScan(srcIP, dstIP string, packet gopacket.Packet) {
	if packet.NetworkLayer() == nil {
		return
	}

	if strings.Contains(srcIP, "192.168") && strings.Contains(dstIP, "192.168") {
		logs = append(logs, fmt.Sprintf("Scan detected: %s -> %s", srcIP, dstIP))
		fmt.Println("ALERT: Potential scan detected!")
	}
}
