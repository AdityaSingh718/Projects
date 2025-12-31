#include "../include/builtin_activities.h"
#include "../include/shell.h"

/* ############## LLM Generated Code Begins ################ */

struct process_info {
    pid_t pid;
    char *command_name;
    char *state;
};

static int compare_process_info(const void *a, const void *b) {
    const struct process_info *proc_a = (const struct process_info *)a;
    const struct process_info *proc_b = (const struct process_info *)b;
    return strcmp(proc_a->command_name, proc_b->command_name);
}

int builtin_activities(int argc, char **argv, char *output_file, int append) {
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

    // Clean up terminated jobs first
    cleanup_terminated_jobs();
    
    // Get background jobs
    struct background_job *bg_jobs = get_background_jobs();
    
    // Count active processes and collect process info
    struct process_info processes[MAX_BACKGROUND_JOBS];
    int process_count = 0;
    
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (bg_jobs[i].active) {
            // Check if process still exists
            if (kill(bg_jobs[i].pid, 0) == 0) {
                // Process exists, check its state from /proc/[pid]/stat
                char proc_path[256];
                snprintf(proc_path, sizeof(proc_path), "/proc/%d/stat", bg_jobs[i].pid);
                
                FILE *stat_file = fopen(proc_path, "r");
                if (stat_file) {
                    char state;
                    // Skip to the third field which contains the state
                    fscanf(stat_file, "%*d %*s %c", &state);
                    fclose(stat_file);
                    
                    processes[process_count].pid = bg_jobs[i].pid;
                    processes[process_count].command_name = strdup(bg_jobs[i].command_name);
                    
                    // State 'T' means stopped, others mean running
                    if (state == 'T') {
                        processes[process_count].state = strdup("Stopped");
                    } else {
                        processes[process_count].state = strdup("Running");
                    }
                    process_count++;
                } else {
                    // Can't read proc file, assume it's running if kill(0) succeeded
                    processes[process_count].pid = bg_jobs[i].pid;
                    processes[process_count].command_name = strdup(bg_jobs[i].command_name);
                    processes[process_count].state = strdup("Running");
                    process_count++;
                }
            }
            // If kill(0) failed, process doesn't exist anymore - don't include it
        }
    }
    
    // Sort the processes lexicographically by command name
    qsort(processes, process_count, sizeof(struct process_info), compare_process_info);
    
    // Print the sorted processes
    for (int i = 0; i < process_count; i++) {
        printf("[%d] : %s - %s\n", processes[i].pid, processes[i].command_name, processes[i].state);
        free(processes[i].command_name);
        free(processes[i].state);
    }
    
    // Restore stdout if redirected
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    
    return 0;
}
/* ############## LLM Generated Code Ends ################ */
