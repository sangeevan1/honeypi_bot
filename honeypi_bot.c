#include <ncurses.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IPS 10

// Global arrays to store allowed and disallowed IPs
char allowed_ips[MAX_IPS][20];
char disallowed_ips[MAX_IPS][20];
int allowed_count = 0, disallowed_count = 0;

void init_colors() {
    start_color();
    init_pair(1, COLOR_BLUE, COLOR_BLACK);    // Blue text for titles
    init_pair(2, COLOR_GREEN, COLOR_BLACK);   // Green text for options
    init_pair(3, COLOR_RED, COLOR_BLACK);     // Red text for exit/alerts
    init_pair(4, COLOR_WHITE, COLOR_BLACK);   // White text for normal text
}

void print_title(WINDOW *win, int startx, int starty) {
    attron(COLOR_PAIR(1));
    mvwprintw(win, starty, startx, "HoneyPi_bot");
    attroff(COLOR_PAIR(1));
    mvwprintw(win, starty + 1, startx, "Real-time Traffic Monitoring");
    mvwprintw(win, starty + 2, startx, "Author: Sangeevan");
}

void print_main_menu(WINDOW *win, int startx, int starty) {
    attron(COLOR_PAIR(2));
    mvwprintw(win, starty + 4, startx, "1. Set Trusted IP");
    mvwprintw(win, starty + 5, startx, "2. View Logs");
    mvwprintw(win, starty + 6, startx, "3. Allow/Disallow IP");
    mvwprintw(win, starty + 7, startx, "q. Quit");
    attroff(COLOR_PAIR(2));
}

void print_ip_table(WINDOW *win, int startx, int starty) {
    mvwprintw(win, starty, startx, "Allowed IPs (Index) :");
    for (int i = 0; i < allowed_count; i++) {
        mvwprintw(win, starty + i + 1, startx, "[%d] %s", i + 1, allowed_ips[i]);
    }
    
    mvwprintw(win, starty + allowed_count + 2, startx, "Disallowed IPs (Index) :");
    for (int i = 0; i < disallowed_count; i++) {
        mvwprintw(win, starty + allowed_count + i + 3, startx, "[%d] %s", i + 1, disallowed_ips[i]);
    }
}

void set_trusted_ip(WINDOW *win) {
    char ip[20];
    mvwprintw(win, 10, 0, "Enter IP to add as trusted (or 'exit' to go back): ");
    echo();
    mvwscanw(win, 11, 0, "%s", ip);
    if (strcmp(ip, "exit") == 0) {
        noecho();
        return;
    }
    if (allowed_count < MAX_IPS) {
        strcpy(allowed_ips[allowed_count++], ip);
        mvwprintw(win, 12, 0, "IP %s added as trusted!", ip);
    } else {
        mvwprintw(win, 12, 0, "IP list full. Cannot add more.");
    }
    noecho();
}

void allow_disallow_ip(WINDOW *win) {
    int choice;
    char ip[20];
    while (1) {
        clear();
        print_title(win, 10, 2);
        print_ip_table(win, 10, 5);
        mvwprintw(win, 18, 0, "Enter IP to toggle state (or 'exit' to go back): ");
        echo();
        mvwscanw(win, 19, 0, "%s", ip);
        if (strcmp(ip, "exit") == 0) {
            noecho();
            break;
        }

        // Check if the IP is in allowed list
        int i;
        for (i = 0; i < allowed_count; i++) {
            if (strcmp(allowed_ips[i], ip) == 0) {
                // Move IP from allowed to disallowed
                strcpy(disallowed_ips[disallowed_count++], allowed_ips[i]);
                for (int j = i; j < allowed_count - 1; j++) {
                    strcpy(allowed_ips[j], allowed_ips[j + 1]);
                }
                allowed_count--;
                mvwprintw(win, 21, 0, "IP %s moved to disallowed.", ip);
                noecho();
                break;
            }
        }

        // Check if the IP is in disallowed list
        for (i = 0; i < disallowed_count; i++) {
            if (strcmp(disallowed_ips[i], ip) == 0) {
                // Move IP from disallowed to allowed
                strcpy(allowed_ips[allowed_count++], disallowed_ips[i]);
                for (int j = i; j < disallowed_count - 1; j++) {
                    strcpy(disallowed_ips[j], disallowed_ips[j + 1]);
                }
                disallowed_count--;
                mvwprintw(win, 21, 0, "IP %s moved to allowed.", ip);
                noecho();
                break;
            }
        }

        if (i == allowed_count && i == disallowed_count) {
            mvwprintw(win, 21, 0, "IP %s not found in allowed or disallowed list.", ip);
        }

        refresh();
        wrefresh(win);
        getch(); // Wait for user input to continue
    }
}

void view_logs(WINDOW *win) {
    mvwprintw(win, 10, 0, "Logs will be displayed here. (No logs yet)");
}

void display_submenu(WINDOW *win, int choice) {
    switch (choice) {
        case 1:
            set_trusted_ip(win);  // Set trusted IP
            break;
        case 2:
            view_logs(win);  // View logs
            break;
        case 3:
            allow_disallow_ip(win);  // Allow/Disallow IPs
            break;
        case 'q':
            break;  // Quit the program
        default:
            break;
    }
}

int main() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);  // Hide the cursor

    init_colors(); // Initialize colors
    WINDOW *main_win = newwin(20, 60, 1, 1);
    keypad(main_win, TRUE);
    int choice;

    while (1) {
        clear();
        print_title(main_win, 10, 2);
        print_main_menu(main_win, 10, 5);
        refresh();
        wrefresh(main_win);
        choice = wgetch(main_win);

        if (choice == 'q') {
            break;  // Quit the program
        } else if (choice == '1') {
            display_submenu(main_win, 1);  // Go to Set Trusted IP submenu
        } else if (choice == '2') {
            display_submenu(main_win, 2);  // Go to View Logs submenu
        } else if (choice == '3') {
            display_submenu(main_win, 3);  // Go to Allow/Disallow IP submenu
        }
        wrefresh(main_win);
    }

    endwin();  // End ncurses mode
    return 0;
}
