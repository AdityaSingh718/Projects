#include "../include/E4.h"
#include "../include/shell.h"
#include "../include/E3.h"

/* ############## LLM Generated Code Begins ################ */

int builtin_fg(int argc, char **argv, char *output_file, int append) {
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

    // Check if job number is provided
    if (argc != 2) {
        printf("Usage: fg <job_number>\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Parse job number
    char *endptr;
    int job_number = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || job_number <= 0) {
        printf("Invalid job number: %s\n", argv[1]);
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Get background jobs
    struct background_job *bg_jobs = get_background_jobs();
    
    // Find the job with the given job number
    int job_index = -1;
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (bg_jobs[i].active && bg_jobs[i].job_number == job_number) {
            job_index = i;
            break;
        }
    }

    if (job_index == -1) {
        printf("No such job\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Print the command being brought to foreground
    printf("%s\n", bg_jobs[job_index].command_name);

    // Set this process as the foreground process
    set_foreground_process(bg_jobs[job_index].pid, bg_jobs[job_index].command_name);

    // Send SIGCONT to resume the process if it's stopped
    kill(bg_jobs[job_index].pid, SIGCONT);

    // Remove the job from background jobs list
    free(bg_jobs[job_index].command_name);
    bg_jobs[job_index].active = 0;

    // Wait for the process to complete or be stopped again
    int status;
    pid_t result = waitpid(bg_jobs[job_index].pid, &status, WUNTRACED);
    
    if (result < 0) {
        perror("waitpid");
        clear_foreground_process();
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Check if process was stopped again (Ctrl+Z)
    if (WIFSTOPPED(status)) {
        // Process was stopped - it should have been moved back to background by signal handler
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return 0;
    }

    // Process completed normally - clear foreground process
    clear_foreground_process();

    // Restore stdout if redirected
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }

    // Return appropriate exit status
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return 0;
}

int builtin_bg(int argc, char **argv, char *output_file, int append) {
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

    // Check if job number is provided
    if (argc != 2) {
        printf("Usage: bg <job_number>\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Parse job number
    char *endptr;
    int job_number = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || job_number <= 0) {
        printf("Invalid job number: %s\n", argv[1]);
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Get background jobs
    struct background_job *bg_jobs = get_background_jobs();
    
    // Find the job with the given job number
    int job_index = -1;
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (bg_jobs[i].active && bg_jobs[i].job_number == job_number) {
            job_index = i;
            break;
        }
    }

    if (job_index == -1) {
        printf("No such job\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Check the current state of the process
    char stat_path[512];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", bg_jobs[job_index].pid);
    
    FILE *stat_file = fopen(stat_path, "r");
    if (stat_file == NULL) {
        // Process doesn't exist anymore
        printf("No such job\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    char state;
    // Skip the first two fields (pid and comm) and read the state
    fscanf(stat_file, "%*d %*s %c", &state);
    fclose(stat_file);

    // Check if the job is already running
    if (state == 'R' || state == 'S') {
        printf("Job already running\n");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return 0;
    }

    // Send SIGCONT to resume the stopped process
    if (kill(bg_jobs[job_index].pid, SIGCONT) < 0) {
        perror("kill");
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return -1;
    }

    // Print the job information
    printf("[%d] %s &\n", bg_jobs[job_index].job_number, bg_jobs[job_index].command_name);

    // Restore stdout if redirected
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }

    return 0;
}

/* ############## LLM Generated Code Ends ################ */
