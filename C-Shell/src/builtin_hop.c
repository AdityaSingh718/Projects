#include "../include/builtin_hop.h"

/* ############## LLM Generated Code Begins ################ */
char prev_cwd[4097] = "";   /* stores previous cwd */

int builtin_hop(int argc, char **argv, char *output_file, int append) {
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

    char cwd[PATH_MAX];
    char target[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("hop:getcwd");
        return -1;
    }

    // If no arguments, go to HOME
    if (argc < 2) {
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "hop: HOME not set\n");
            return -1;
        }
        if (chdir(home) != 0) {
            printf("No such directory!\n");
            if (saved_stdout >= 0) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            return 0;
        }
        strncpy(prev_cwd, cwd, sizeof(prev_cwd));
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return 0;
    }

    // Process each argument sequentially
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        
        // Get current directory before changing
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            perror("hop:getcwd");
            return -1;
        }

        /* Handle special cases */
        if (strcmp(arg, "~") == 0) {
            strncpy(target, homedir, sizeof(target));
        } else if (strcmp(arg, ".") == 0) {
            /* do nothing - stay in current directory */
            continue;
        } else if (strcmp(arg, "..") == 0) {
            if (strcmp(cwd, "/") == 0) {
                /* already at root → do nothing */
                continue;
            }
            strncpy(target, "..", sizeof(target));
        } else if (strcmp(arg, "-") == 0) {
            if (prev_cwd[0] == '\0') {
                /* no previous cwd */
                continue;
            }
            strncpy(target, prev_cwd, sizeof(target));
        } else {
            /* normal path */
            strncpy(target, arg, sizeof(target));
        }

        /* change directory */
        if (chdir(target) != 0) {
            printf("No such directory!\n");
            /* Restore stdout before returning */
            if (saved_stdout >= 0) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            return 0;
        }

        /* update prev_cwd only on successful directory change */
        strncpy(prev_cwd, cwd, sizeof(prev_cwd));
    }

    /* Restore stdout */
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    
    return 0;
}
/* ############## LLM Generated Code Ends ################ */