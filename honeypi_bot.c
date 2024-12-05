#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#define LOG_FILE "honeypot_alerts.log"
#define MAX_IP_LEN 16
#define MAX_INPUT 100
#define MAX_ALERT_LEN 200

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
void *network_monitoring(void *arg);

// Intrusion Alert
char alert_message[MAX_ALERT_LEN] = "";

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

// Function to check for 'q' input to exit
int check_exit(const char *input) {
    if (strcmp(input, "q") == 0 || strcmp(input, "Q") == 0) {
        printf("Returning to main menu...\n");
        sleep(1);
        return 1;
    }
    return 0;
}

// Function to define honeypot and SCADA IPs
void define_ips() {
    char honeypot_ip[MAX_IP_LEN], scada_ip[MAX_IP_LEN];

    printf("Enter the Honeypot IP address (or press 'q' to return): ");
    scanf("%s", honeypot_ip);
    if (check_exit(honeypot_ip)) return;

    printf("Enter the SCADA IP address (or press 'q' to return): ");
    scanf("%s", scada_ip);
    if (check_exit(scada_ip)) return;

    // Add Honeypot IP
    // Add your logic to add Honeypot and SCADA IPs here
    log_alert("Honeypot and SCADA IPs have been added as trusted.");
    printf("Honeypot and SCADA IPs have been added as trusted.\n");
}

// Function to display trusted IPs
void display_trusted_ips() {
    printf("\033[1;34m--- Trusted IPs ---\033[0m\n");
    // Display trusted IPs logic here
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

    // Allow/Disallow logic here
    log_alert("Allowed/Disallowed IP action performed.");
}

// Function to detect vulnerable traffic
void detect_vulnerable_traffic() {
    printf("Detecting vulnerable traffic...\n");
    log_alert("Vulnerable traffic detection started.");
    system("tcpdump -i eth0 -nn -v 'tcp port 502 or tcp port 102 or tcp port 135'"); // Example vulnerable ports
    log_alert("Vulnerable traffic detection stopped.");
}

// Function to view logs
void view_logs() {
    printf("\033[1;34m--- Logs ---\033[0m\n");
    char command[100];
    snprintf(command, 100, "cat %s", LOG_FILE);
    system(command);
    printf("Press any key to return to the main menu...");
    getchar(); getchar(); // Wait for user input
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

// Function to exit the application
void exit_application() {
    printf("Exiting...\n");
    log_alert("Application exited by user.");
    exit(0);
}

// Network Monitoring (background thread)
void *network_monitoring(void *arg) {
    while (1) {
        // Simulate intrusion detection (e.g., Nmap or scanning tool detection)
        // Example detection for Nmap or other common attack tools
        // This part should use tools like `nmap` or `tcpdump` to detect suspicious activities
        // For simplicity, we are using a basic check
        FILE *fp = popen("netstat -an | grep ':80 ' | wc -l", "r");
        if (fp) {
            int count;
            fscanf(fp, "%d", &count);
            fclose(fp);
            if (count > 5) { // Example threshold for alert (e.g., multiple incoming connections from same IP)
                snprintf(alert_message, MAX_ALERT_LEN, "Intrusion detected: Multiple connections detected on port 80.");
                log_alert(alert_message);
            }
        }

        sleep(2); // Sleep for a few seconds before checking again
    }
}

// Main menu
int main() {
    int choice;
    pthread_t monitoring_thread;

    // Start network monitoring in the background
    pthread_create(&monitoring_thread, NULL, network_monitoring, NULL);

    while (1) {
        clear_screen();
        display_heading();

        // Show any intrusion alert if present
        if (strlen(alert_message) > 0) {
            printf("\033[0;31m%s\033[0m\n", alert_message); // Display alert in red
            memset(alert_message, 0, MAX_ALERT_LEN); // Clear the alert after showing it
        }

        printf("1. Define Honeypot and SCADA IPs\n");
        printf("2. View Trusted IPs\n");
        printf("3. Allow/Disallow IP\n");
        printf("4. View Logs\n");
        printf("5. Start Traffic Monitoring\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                define_ips();
                break;
            case 2:
                display_trusted_ips();
                break;
            case 3:
                allow_disallow_ip();
                break;
            case 4:
                view_logs();
                break;
            case 5:
                start_monitoring();
                break;
            case 6:
                exit_application();
                break;
            default:
                printf("Invalid choice. Try again.\n");
                sleep(2);
        }
    }

    return 0;
}
