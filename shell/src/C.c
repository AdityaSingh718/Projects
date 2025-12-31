#include "../include/C.h"
#include "../include/E3.h"

int execute_command(int argc, char **argv, char *input_file, char *output_file, int append) {
    if (argc == 0) return 0;
    char **exec_argv = malloc((argc + 1) * sizeof(char *));
    for (int i = 0; i < argc; i++) {
        exec_argv[i] = argv[i];
    }
    exec_argv[argc] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        free(exec_argv);
        return -1;
    }

    if (pid == 0) {
        // --- child ---
        
        if (input_file != NULL) {
            int fd = open(input_file, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "No such file or directory\n");
                free(exec_argv);
                _exit(1);
            }

            if (dup2(fd, STDIN_FILENO) < 0) {
                perror("dup2");
                close(fd);
                free(exec_argv);
                _exit(1);
            }
            close(fd);
        }
        
  
        if (output_file != NULL) {
            int flags = O_WRONLY | O_CREAT;
            if (append) {
                flags |= O_APPEND;  // >> - append to file
            } else {
                flags |= O_TRUNC;   // > - truncate (wipe) file
            }
            
            int fd = open(output_file, flags, 0644);
            if (fd < 0) {
                if (errno == EACCES || errno == EPERM) {
                    fprintf(stderr, "Unable to create file for writing\n");
                } else {
                    fprintf(stderr, "Error opening %s: %s\n", output_file, strerror(errno));
                }
                free(exec_argv);
                _exit(1);
            }

            if (dup2(fd, STDOUT_FILENO) < 0) {
                perror("dup2");
                close(fd);
                free(exec_argv);
                _exit(1);
            }
            close(fd);
        }

        execvp(exec_argv[0], exec_argv);
        // Print error message when command is not found
        printf("Command not found!\n");
        free(exec_argv);
        _exit(127);
    } else {
        // --- parent ---
        free(exec_argv);
        
        // Set this as the foreground process
        set_foreground_process(pid, argv[0]);
        
        int status;
        pid_t result = waitpid(pid, &status, WUNTRACED);
        
        if (result < 0) {
            perror("waitpid");
            clear_foreground_process();
            return -1;
        }
        
        // Check if process was stopped (Ctrl+Z)
        if (WIFSTOPPED(status)) {
            // Process was stopped - it's now in background, don't clear foreground_process
            // The signal handler already moved it to background jobs
            return 0;  // Return success for stopped process
        }
        
        // Process completed normally - clear foreground process
        clear_foreground_process();
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);  // Standard convention for signal termination
        }
        
        return 0;
    }
}
