#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define LOG_FILE "honeypot_alerts.log"
#define MAX_IP_LEN 16
#define MAX_INPUT 100
#define MAX_ALERT_LEN 200
#define HONEYPOT_IP "192.168.1.100"  // Simulated honeypot IP
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

// Function to detect vulnerable traffic and highlight in red
void detect_vulnerable_traffic() {
    printf("Detecting vulnerable traffic...\n");
    log_alert("Vulnerable traffic detection started.");

    // Example of detecting traffic on specific ports
    FILE *fp = popen("tcpdump -i eth0 -nn -v 'tcp port " VULNERABLE_PORTS "'", "r");
    if (fp) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), fp)) {
            // Highlight vulnerable traffic in red
            printf("\033[0;31m%s\033[0m", buffer);  // Red color
        }
        fclose(fp);
    }
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

// Simulated redirect of vulnerable traffic to Honeypot
void redirect_to_honeypot() {
    printf("Redirecting vulnerable traffic to honeypot at IP: %s\n", HONEYPOT_IP);
    log_alert("Vulnerable traffic redirected to honeypot.");
}

// Network Monitoring (forked process)
void start_network_monitoring() {
    pid_t pid = fork();

    if (pid == 0) {  // Child process (network monitoring)
        while (1) {
            // Simulate intrusion detection (e.g., Nmap or scanning tool detection)
            FILE *fp = popen("netstat -an | grep ':80 ' | wc -l", "r");
            if (fp) {
                int count;
                fscanf(fp, "%d", &count);
                fclose(fp);
                if (count > 5) { // Example threshold for alert (e.g., multiple incoming connections from same IP)
                    snprintf(alert_message, MAX_ALERT_LEN, "Intrusion detected: Multiple connections detected on port 80.");
                    log_alert(alert_message);
                    redirect_to_honeypot();  // Redirect to honeypot
                }
            }

            sleep(2); // Sleep for a few seconds before checking again
        }
    } else if (pid < 0) {
        perror("Fork failed");
        exit(1);
    }
}

// Main menu
int main() {
    int choice;

    // Start network monitoring in the background
    start_network_monitoring();

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
