
#include "../include/signals.h"
#include "../include/shell.h"

/* ############## LLM Generated Code Begins ################ */

// Global variables for tracking foreground process
pid_t foreground_pid = 0;
char *foreground_cmd = NULL;

// Signal handler for SIGINT (Ctrl+C)
void sigint_handler(int sig) {
    if (foreground_pid > 0) {
        // Send SIGINT to the foreground process
        kill(foreground_pid, SIGINT);
    } else {
        // No foreground process - move to new line and show prompt
        printf("\n");
        shellprompt();
        fflush(stdout);
    }
    // Don't terminate the shell itself
}

// Signal handler for SIGTSTP (Ctrl+Z)
void sigtstp_handler(int sig) {
    if (foreground_pid > 0) {
        // Send SIGTSTP to the foreground process
        kill(foreground_pid, SIGTSTP);
        
        // Add the stopped process to background jobs
        struct background_job *bg_jobs = get_background_jobs();
        
        // Find an empty slot and add the stopped job
        for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
            if (!bg_jobs[i].active) {
                bg_jobs[i].pid = foreground_pid;
                bg_jobs[i].command_name = strdup(foreground_cmd ? foreground_cmd : "unknown");
                bg_jobs[i].active = 1;
                
                // Find the next job number
                int max_job_num = 0;
                for (int j = 0; j < MAX_BACKGROUND_JOBS; j++) {
                    if (bg_jobs[j].active && j != i && bg_jobs[j].job_number > max_job_num) {
                        max_job_num = bg_jobs[j].job_number;
                    }
                }
                bg_jobs[i].job_number = max_job_num + 1;
                
                // Print the stopped message
                printf("\n[%d] Stopped %s\n", bg_jobs[i].job_number, bg_jobs[i].command_name);
                fflush(stdout);
                break;
            }
        }
        
        // Clear the foreground process so the shell doesn't wait for it
        clear_foreground_process();
    } else {
        // No foreground process - move to new line and show prompt
        printf("\n");
        shellprompt();
        fflush(stdout);
    }
    // Don't stop the shell itself - return control to shell prompt
}

// Setup signal handlers
void setup_signal_handlers(void) {
    struct sigaction sa_int, sa_tstp;
    
    // Setup SIGINT handler (Ctrl+C)
    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa_int, NULL);
    
    // Setup SIGTSTP handler (Ctrl+Z)
    sa_tstp.sa_handler = sigtstp_handler;
    sigemptyset(&sa_tstp.sa_mask);
    sa_tstp.sa_flags = SA_RESTART;
    sigaction(SIGTSTP, &sa_tstp, NULL);
}

// Set the current foreground process
void set_foreground_process(pid_t pid, const char *cmd) {
    foreground_pid = pid;
    if (foreground_cmd) {
        free(foreground_cmd);
    }
    foreground_cmd = cmd ? strdup(cmd) : NULL;
}

// Clear the current foreground process
void clear_foreground_process(void) {
    foreground_pid = 0;
    if (foreground_cmd) {
        free(foreground_cmd);
        foreground_cmd = NULL;
    }
}

// Check for EOF condition (Ctrl+D)
int check_eof(char *input) {
    return (input == NULL);
}

// Cleanup and exit on Ctrl+D
void cleanup_and_exit(void) {
    // Send SIGKILL to all background processes
    struct background_job *bg_jobs = get_background_jobs();
    
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (bg_jobs[i].active) {
            // Check if process still exists before killing it
            if (kill(bg_jobs[i].pid, 0) == 0) {
                kill(bg_jobs[i].pid, SIGKILL);
            }
            if (bg_jobs[i].command_name) {
                free(bg_jobs[i].command_name);
            }
            bg_jobs[i].active = 0;
        }
    }
    
    // Give a brief moment for processes to be cleaned up
    struct timespec delay = {0, 10000000}; // 10ms delay (10,000,000 nanoseconds)
    nanosleep(&delay, NULL);
    
    // Clear foreground process info
    clear_foreground_process();
    
    printf("logout\n");
    fflush(stdout);
    exit(0);
}

/* ############## LLM Generated Code Ends ################ */
