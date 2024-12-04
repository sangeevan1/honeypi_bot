#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define LOG_FILE "honeypot_alerts.log"
#define MAX_IP_LEN 16
#define MAX_INPUT 100

// Function prototypes
void log_alert(const char *message);
void detect_vulnerable_traffic();
void allow_disallow_ip();
void display_trusted_ips();
void view_logs();
void clear_screen();
void start_monitoring();
void display_heading();

typedef struct {
    char ip[MAX_IP_LEN];
    char status[10]; // "Allowed" or "Disallowed"
} IPRecord;

IPRecord trusted_ips[100]; // List of trusted IPs
int ip_count = 0;          // Number of IPs in the list

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

    printf("\033[0;31mALERT: %s\033[0m\n", message);
}

// Function to detect vulnerable traffic
void detect_vulnerable_traffic() {
    printf("Detecting vulnerable traffic...\n");
    log_alert("Vulnerable traffic detection started.");
    system("tcpdump -i eth0 -nn -v 'tcp port 502 or tcp port 102 or tcp port 135'"); // Example vulnerable ports
    log_alert("Vulnerable traffic detection stopped.");
}

// Function to allow or disallow an IP
void allow_disallow_ip() {
    char ip[MAX_IP_LEN], action[10];

    printf("Enter the IP to allow/disallow: ");
    scanf("%s", ip);
    printf("Enter action (allow/disallow): ");
    scanf("%s", action);

    if (strcmp(action, "allow") == 0) {
        snprintf(trusted_ips[ip_count].ip, MAX_IP_LEN, "%s", ip);
        snprintf(trusted_ips[ip_count].status, 10, "Allowed");
        ip_count++;
        char command[100];
        snprintf(command, 100, "iptables -A INPUT -s %s -j ACCEPT", ip);
        system(command);
        log_alert("Allowed IP added to firewall");
    } else if (strcmp(action, "disallow") == 0) {
        char command[100];
        snprintf(command, 100, "iptables -A INPUT -s %s -j DROP", ip);
        system(command);
        log_alert("Disallowed IP added to firewall");
    } else {
        printf("Invalid action. Please use 'allow' or 'disallow'.\n");
    }
}

// Function to display trusted IPs
void display_trusted_ips() {
    printf("\033[1;34m--- Trusted IPs ---\033[0m\n");
    for (int i = 0; i < ip_count; i++) {
        printf("%s -> %s\n", trusted_ips[i].ip, trusted_ips[i].status);
    }
}

// Function to view logs
void view_logs() {
    printf("\033[1;34m--- Logs ---\033[0m\n");
    char command[100];
    snprintf(command, 100, "cat %s", LOG_FILE);
    system(command);
}

// Function to clear screen
void clear_screen() {
    system("clear");
}

// Function to start monitoring (vulnerable traffic detection)
void start_monitoring() {
    clear_screen();
    printf("Starting monitoring...\n");
    log_alert("Monitoring started.");
    detect_vulnerable_traffic();
}

// Function to display heading
void display_heading() {
    printf("\033[1;34m=== HoneyPi - Honeypot Monitor ===\033[0m\n");
}

// Main menu
int main() {
    int choice;

    while (1) {
        clear_screen();
        display_heading();
        printf("1. Set Trusted IP\n");
        printf("2. View Trusted IPs\n");
        printf("3. Allow/Disallow IP\n");
        printf("4. View Logs\n");
        printf("5. Start Traffic Monitoring\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                allow_disallow_ip();
                sleep(2);
                break;
            case 2:
                display_trusted_ips();
                sleep(2);
                break;
            case 3:
                allow_disallow_ip();
                sleep(2);
                break;
            case 4:
                view_logs();
                sleep(2);
                break;
            case 5:
                start_monitoring();
                sleep(2);
                break;
            case 6:
                printf("Exiting...\n");
                exit(0);
                break;
            default:
                printf("Invalid choice. Try again.\n");
                sleep(2);
        }
    }

    return 0;
}
