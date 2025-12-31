#include "../include/E2.h"

/* ############## LLM Generated Code Begins ################ */

int builtin_ping(int argc, char **argv, char *output_file, int append) {
    int saved_stdout = -1;
    if (output_file != NULL) {
        int flags = O_WRONLY | O_CREAT;
        if (append) {
            flags |= O_APPEND;
        } else {
            flags |= O_TRUNC;
        }
        
        int fd = open(output_file, flags, 0644);
        if (fd < 0) {
            fprintf(stderr, "Error opening %s: %s\n", output_file, strerror(errno));
            return -1;
        }
        
        saved_stdout = dup(STDOUT_FILENO);
        if (saved_stdout < 0 || dup2(fd, STDOUT_FILENO) < 0) {
            perror("redirection failed");
            close(fd);
            if (saved_stdout >= 0) close(saved_stdout);
            return -1;
        }
        close(fd);
    }

    // Check if correct number of arguments
    if (argc != 3) {
        printf("Usage: ping <pid> <signal_number>\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Parse PID
    char *endptr;
    pid_t pid = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || pid <= 0) {
        printf("Invalid PID: %s\n", argv[1]);
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Parse signal number
    int original_signal = strtol(argv[2], &endptr, 10);
    if (*endptr != '\0') {
        printf("Invalid signal number: %s\n", argv[2]);
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Calculate actual signal (modulo 32)
    int actual_signal = original_signal % 32;
    
    // Handle special case where modulo gives 0 (should be 32)
    if (actual_signal == 0 && original_signal != 0) {
        actual_signal = 32;
    }

    // Send the signal
    if (kill(pid, actual_signal) == 0) {
        printf("Sent signal %d to process with pid %d\n", actual_signal, pid);
    } else {
        if (errno == ESRCH) {
            printf("No such process found\n");
        } else {
            printf("Failed to send signal: %s\n", strerror(errno));
        }
    }

    // Restore stdout if redirected
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }

    return 0;
}
/* ############## LLM Generated Code Ends ################ */
