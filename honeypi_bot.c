#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>

#define MAX_IP_LENGTH 16
#define MAX_NAME_LENGTH 32
#define MAX_LOGS 100

// Data structures to hold the IP addresses
char trusted_ips[10][MAX_IP_LENGTH];
char logs[MAX_LOGS][256];
int log_index = 0;

// Function declarations
void show_main_menu(WINDOW *win);
void set_trusted_ip(WINDOW *win);
void view_logs(WINDOW *win);
void allow_disallow_ip(WINDOW *win);
void input_ladder_command(WINDOW *win);
void log_activity(const char *message);
void add_trusted_ip(const char *ip, const char *name);

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

void show_main_menu(WINDOW *win) {
    int choice;
    while (1) {
        // Clear the window
        werase(win);

        // Print the menu
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

void set_trusted_ip(WINDOW *win) {
    char ip[MAX_IP_LENGTH];
    char name[MAX_NAME_LENGTH];

    // Clear window for new menu
    werase(win);

    // Request IP input
    mvwprintw(win, 1, 1, "Enter IP to set as trusted:");
    wrefresh(win);
    echo();
    mvwgetstr(win, 2, 1, ip);
    noecho();

    // Request Name input
    mvwprintw(win, 3, 1, "Enter name for the trusted IP:");
    wrefresh(win);
    echo();
    mvwgetstr(win, 4, 1, name);
    noecho();

    // Add to trusted IP list
    add_trusted_ip(ip, name);

    // Log the activity
    log_activity("New trusted IP added");

    // Show success message
    mvwprintw(win, 6, 1, "Trusted IP added successfully!");
    wrefresh(win);
    getch();
}

void view_logs(WINDOW *win) {
    // Clear window for log display
    werase(win);

    // Print the logs
    mvwprintw(win, 1, 1, "System Logs:");
    for (int i = 0; i < log_index; i++) {
        mvwprintw(win, 3 + i, 1, logs[i]);
    }
    wrefresh(win);

    // Wait for user input before returning to the main menu
    getch();
}

void allow_disallow_ip(WINDOW *win) {
    char ip[MAX_IP_LENGTH];
    char action[10];

    // Clear window for allow/disallow menu
    werase(win);

    // Request IP input
    mvwprintw(win, 1, 1, "Enter IP to allow/disallow:");
    wrefresh(win);
    echo();
    mvwgetstr(win, 2, 1, ip);
    noecho();

    // Request action input (allow or disallow)
    mvwprintw(win, 3, 1, "Enter action (allow/disallow):");
    wrefresh(win);
    echo();
    mvwgetstr(win, 4, 1, action);
    noecho();

    // Log the action
    char log_message[256];
    sprintf(log_message, "IP %s marked as %s", ip, action);
    log_activity(log_message);

    // Show success message
    mvwprintw(win, 6, 1, "Action completed!");
    wrefresh(win);
    getch();
}

void input_ladder_command(WINDOW *win) {
    char command[256];

    // Clear window for command input
    werase(win);

    // Request ladder command input
    mvwprintw(win, 1, 1, "Enter Ladder Command:");
    wrefresh(win);
    echo();
    mvwgetstr(win, 2, 1, command);
    noecho();

    // Log the ladder command
    log_activity(command);

    // Show success message
    mvwprintw(win, 4, 1, "Ladder Command Executed!");
    wrefresh(win);
    getch();
}

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

void add_trusted_ip(const char *ip, const char *name) {
    // Just add to the trusted IP list (can be expanded to validate the IP)
    printf("Adding trusted IP: %s (%s)\n", ip, name);
}
