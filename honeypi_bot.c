#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>

#define MAX_IP_LENGTH 16
#define MAX_NAME_LENGTH 32
#define MAX_LOGS 100
#define MAX_IPS 20

// Data structures
char trusted_ips[10][MAX_IP_LENGTH];
char allowed_ips[MAX_IPS][MAX_IP_LENGTH];
char disallowed_ips[MAX_IPS][MAX_IP_LENGTH];
char logs[MAX_LOGS][256];
int log_index = 0;
int allowed_index = 0;
int disallowed_index = 0;

// Function declarations
void show_main_menu(WINDOW *win);
void set_trusted_ip(WINDOW *win);
void view_logs(WINDOW *win);
void allow_disallow_ip(WINDOW *win);
void input_ladder_command(WINDOW *win);
void log_activity(const char *message);
void add_trusted_ip(const char *ip, const char *name);
void add_ip_to_list(char *ip, char *state);
void display_ips(WINDOW *win);

// Main function
int main() {
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(0); // Hide cursor
    keypad(stdscr, TRUE);

    // Create a window for menu display
    int height = 10, width = 40;
    int start_y = (LINES - height) / 2;
    int start_x = (COLS - width) / 2;
    WINDOW *win = newwin(height, width, start_y, start_x);
    refresh();

    // Show the main menu
    show_main_menu(win);

    // End ncurses mode
    endwin();
    return 0;
}

// Main menu
void show_main_menu(WINDOW *win) {
    int choice;
    while (1) {
        // Clear the window
        werase(win);

        // Print the menu with heading
        box(win, 0, 0);
        mvwprintw(win, 1, 1, "Main Menu");
        mvwprintw(win, 3, 1, "1. Set Trusted IP");
        mvwprintw(win, 4, 1, "2. View Logs");
        mvwprintw(win, 5, 1, "3. Allow/Disallow IP");
        mvwprintw(win, 6, 1, "4. Input Ladder Command");
        mvwprintw(win, 7, 1, "q. Quit");

        // Refresh the window to show the updated menu
        wrefresh(win);

        // Get user input
        choice = wgetch(win);

        // Handle user choice
        switch (choice) {
            case '1':
                set_trusted_ip(win);
                break;
            case '2':
                view_logs(win);
                break;
            case '3':
                allow_disallow_ip(win);
                break;
            case '4':
                input_ladder_command(win);
                break;
            case 'q':
                return; // Quit the program
            default:
                break;
        }
    }
}

// Set Trusted IP
void set_trusted_ip(WINDOW *win) {
    char ip[MAX_IP_LENGTH];
    char name[MAX_NAME_LENGTH];

    // Clear window for new menu
    werase(win);
    box(win, 0, 0);

    // Print heading
    mvwprintw(win, 1, 1, "Set Trusted IP");
    mvwprintw(win, 3, 1, "Enter IP to set as trusted (Press 'q' to quit):");
    wrefresh(win);
    echo();
    mvwgetstr(win, 4, 1, ip);

    // Check if 'q' is pressed
    if (strcmp(ip, "q") == 0) {
        noecho();
        return; // Exit and return to main menu
    }

    mvwprintw(win, 6, 1, "Enter name for the trusted IP:");
    wrefresh(win);
    mvwgetstr(win, 7, 1, name);

    // Check if 'q' is pressed
    if (strcmp(name, "q") == 0) {
        noecho();
        return; // Exit and return to main menu
    }

    // Add to trusted IP list
    add_trusted_ip(ip, name);

    // Log the activity
    log_activity("New trusted IP added");

    // Show success message
    mvwprintw(win, 9, 1, "Trusted IP added successfully!");
    wrefresh(win);
    getch();
    noecho();
}

// View Logs
void view_logs(WINDOW *win) {
    // Clear window for log display
    werase(win);
    box(win, 0, 0);

    // Print heading
    mvwprintw(win, 1, 1, "View Logs");
    mvwprintw(win, 3, 1, "System Logs (Press 'q' to quit):");

    // Print the logs
    for (int i = 0; i < log_index; i++) {
        mvwprintw(win, 5 + i, 1, logs[i]);
    }
    wrefresh(win);

    // Wait for user input before returning to the main menu
    char key = wgetch(win);
    if (key == 'q') {
        return; // Exit and return to the main menu
    }
}

// Allow/Disallow IP
void allow_disallow_ip(WINDOW *win) {
    char ip[MAX_IP_LENGTH];
    char action[10];

    // Clear window for allow/disallow menu
    werase(win);
    box(win, 0, 0);

    // Print heading
    mvwprintw(win, 1, 1, "Allow/Disallow IP");
    mvwprintw(win, 3, 1, "Enter IP to allow/disallow (Press 'q' to quit):");
    wrefresh(win);
    echo();
    mvwgetstr(win, 4, 1, ip);

    // Check if 'q' is pressed
    if (strcmp(ip, "q") == 0) {
        noecho();
        return; // Exit and return to main menu
    }

    mvwprintw(win, 6, 1, "Enter action (allow/disallow):");
    wrefresh(win);
    mvwgetstr(win, 7, 1, action);

    // Check if 'q' is pressed
    if (strcmp(action, "q") == 0) {
        noecho();
        return; // Exit and return to main menu
    }

    // Validate action and update the lists accordingly
    if (strcmp(action, "allow") == 0) {
        add_ip_to_list(ip, "allowed");
    } else if (strcmp(action, "disallow") == 0) {
        add_ip_to_list(ip, "disallowed");
    }

    // Show success message
    mvwprintw(win, 9, 1, "Action completed!");
    wrefresh(win);
    getch();
    noecho();
}

// Input Ladder Command
void input_ladder_command(WINDOW *win) {
    char command[256];

    // Clear window for command input
    werase(win);
    box(win, 0, 0);

    // Print heading
    mvwprintw(win, 1, 1, "Input Ladder Command");
    mvwprintw(win, 3, 1, "Enter Ladder Command (Press 'q' to quit):");
    wrefresh(win);
    echo();
    mvwgetstr(win, 4, 1, command);

    // Check if 'q' is pressed
    if (strcmp(command, "q") == 0) {
        noecho();
        return; // Exit and return to main menu
    }

    // Log the ladder command
    log_activity(command);

    // Show success message
    mvwprintw(win, 6, 1, "Ladder Command Executed!");
    wrefresh(win);
    getch();
    noecho();
}

// Log Activity
void log_activity(const char *message) {
    if (log_index < MAX_LOGS) {
        strcpy(logs[log_index], message);
        log_index++;
    } else {
        // Log buffer is full, overwrite the oldest log
        for (int i = 1; i < MAX_LOGS; i++) {
            strcpy(logs[i - 1], logs[i]);
        }
        strcpy(logs[MAX_LOGS - 1], message);
    }
}

// Add Trusted IP
void add_trusted_ip(const char *ip, const char *name) {
    // Just add to the trusted IP list (can be expanded to validate the IP)
    printf("Adding trusted IP: %s (%s)\n", ip, name);
}

// Add IP to Allow/Disallow List
void add_ip_to_list(char *ip, char *state) {
    if (strcmp(state, "allowed") == 0 && allowed_index < MAX_IPS) {
        strcpy(allowed_ips[allowed_index], ip);
        allowed_index++;
        log_activity("IP added to allow list");
    } else if (strcmp(state, "disallowed") == 0 && disallowed_index < MAX_IPS) {
        strcpy(disallowed_ips[disallowed_index], ip);
        disallowed_index++;
        log_activity("IP added to disallow list");
    }
}

// Display Allowed and Disallowed IPs
void display_ips(WINDOW *win) {
    werase(win);
    box(win, 0, 0);

    mvwprintw(win, 1, 1, "Allowed IPs:");
    for (int i = 0; i < allowed_index; i++) {
        mvwprintw(win, 2 + i, 1, allowed_ips[i]);
    }

    mvwprintw(win, 1, 20, "Disallowed IPs:");
    for (int i = 0; i < disallowed_index; i++) {
        mvwprintw(win, 2 + i, 20, disallowed_ips[i]);
    }
    wrefresh(win);
}
