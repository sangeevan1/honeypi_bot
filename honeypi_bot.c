#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define LOG_FILE "honeypot_alerts.log"
#define MAX_IP_LEN 16
#define MAX_INPUT 100
#define MAX_ALERT_LEN 200
#define HONEYPOT_IP "192.168.96.114"  // Predefined Honeypot IP
#define SCADA_IP "192.168.90.5"      // Predefined SCADA IP
#define PLC_IP "192.168.96.2"        // Predefined PLC IP
#define VULNERABLE_PORTS "502|102|135"  // Example vulnerable ports (Modbus, SCADA, etc.)

// Function prototypes
void log_alert(const char *message);
void define_ips();
void display_trusted_ips();
void allow_disallow_ip();
void detect_vulnerable_traffic();
void view_logs();
void clear_screen();
void start_monitoring();
void display_heading();
void exit_application();
int check_exit(const char *input);
void start_network_monitoring();
void update_trusted_ips(const char *ip, const char *action);
void apply_iptables_rules(const char *ip, const char *action);

// Intrusion Alert
char alert_message[MAX_ALERT_LEN] = "";
char trusted_ips[10][MAX_IP_LEN] = {HONEYPOT_IP, SCADA_IP, PLC_IP};
int trusted_ip_count = 3;

// Function to log alerts to a file
void log_alert(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline

    fprintf(log_file, "[%s] %s\n", time_str, message);
    fclose(log_file);

    // Print alert message in red
    printf("\033[0;31mALERT: %s\033[0m\n", message);
}

// Function to update trusted IPs dynamically
void update_trusted_ips(const char *ip, const char *action) {
    if (strcmp(action, "allow") == 0) {
        if (trusted_ip_count < 10) {
            strcpy(trusted_ips[trusted_ip_count++], ip);
            printf("IP %s added to trusted list.\n", ip);
            apply_iptables_rules(ip, "ALLOW");
        } else {
            printf("Trusted IP list is full.\n");
        }
    } else if (strcmp(action, "disallow") == 0) {
        for (int i = 0; i < trusted_ip_count; i++) {
            if (strcmp(trusted_ips[i], ip) == 0) {
                for (int j = i; j < trusted_ip_count - 1; j++) {
                    strcpy(trusted_ips[j], trusted_ips[j + 1]);
                }
                trusted_ip_count--;
                printf("IP %s removed from trusted list.\n", ip);
                apply_iptables_rules(ip, "DISALLOW");
                return;
            }
        }
        printf("IP %s not found in trusted list.\n", ip);
    }
}

// Apply iptables rules to allow or disallow IPs
void apply_iptables_rules(const char *ip, const char *action) {
    char command[100];
    if (strcmp(action, "ALLOW") == 0) {
        snprintf(command, sizeof(command), "sudo iptables -A INPUT -s %s -j ACCEPT", ip);
    } else if (strcmp(action, "DISALLOW") == 0) {
        snprintf(command, sizeof(command), "sudo iptables -D INPUT -s %s -j ACCEPT", ip);
    }
    system(command);
}

// Function to check for 'q' input to exit
int check_exit(const char *input) {
    if (strcmp(input, "q") == 0 || strcmp(input, "Q") == 0) {
        printf("Returning to main menu...\n");
        sleep(1);
        return 1;
    }
    return 0;
}

// Function to display trusted IPs
void display_trusted_ips() {
    printf("\033[1;34m--- Trusted IPs ---\033[0m\n");
    for (int i = 0; i < trusted_ip_count; i++) {
        printf("%d. %s\n", i + 1, trusted_ips[i]);
    }
    printf("Press any key to return to the main menu...");
    getchar(); getchar(); // Wait for user input
}

// Function to allow or disallow an IP
void allow_disallow_ip() {
    char ip[MAX_IP_LEN], action[10];

    printf("Enter the IP to allow/disallow (or press 'q' to return): ");
    scanf("%s", ip);
    if (check_exit(ip)) return;

    printf("Enter action (allow/disallow) (or press 'q' to return): ");
    scanf("%s", action);
    if (check_exit(action)) return;

    update_trusted_ips(ip, action);
}

// Function to detect vulnerable traffic
void detect_vulnerable_traffic() {
    printf("Detecting vulnerable traffic...\n");
    log_alert("Vulnerable traffic detection started.");

    FILE *fp = popen("sudo tcpdump -i eth0 -nn -v 'tcp port " VULNERABLE_PORTS "'", "r");
    if (fp == NULL) {
        log_alert("Error starting tcpdump.");
        printf("\033[0;31mError starting tcpdump.\033[0m\n");
        return;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, HONEYPOT_IP) != NULL) {
            printf("\033[0;32mHoneypot traffic: %s\033[0m", buffer);
        } else {
            printf("\033[0;31m%s\033[0m", buffer);
        }
    }

    pclose(fp);
    log_alert("Vulnerable traffic detection stopped.");
}

// Main menu logic continues unchanged...
