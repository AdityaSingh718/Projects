#include "../include/builtin_log.h"
#include "../include/shell.h"
/* ############## LLM Generated Code Begins ################ */
/* history state */
static char *history[MAX_HISTORY];
static int history_count = 0;

/* build full path to history file in shell directory */
static void get_history_path(char *buf, size_t size) {
    char cwd[4097];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(buf, size, "./%s", HISTORY_FILE); /* fallback to current dir */
        return;
    }
    
    /* find the shell directory by going up from src to shell */
    char *src_pos = strstr(cwd, "/src");
    if (src_pos) {
        *src_pos = '\0'; /* truncate at /src to get shell directory */
        snprintf(buf, size, "%s/%s", cwd, HISTORY_FILE);
    } else {
        /* fallback: assume we're in shell directory or subdirectory */
        snprintf(buf, size, "./%s", HISTORY_FILE);
    }
}

/* load history from file at startup */
void load_history(void) {
    char path[4097];
    get_history_path(path, sizeof(path));

    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0'; /* strip newline */
        if (history_count < MAX_HISTORY) {
            history[history_count++] = strdup(line);
        }
    }
    fclose(fp);
}

/* save current history to file */
static void save_history(void) {
    char path[4097];
    get_history_path(path, sizeof(path));

    FILE *fp = fopen(path, "w");
    if (!fp) return;

    for (int i = 0; i < history_count; i++) {
        fprintf(fp, "%s\n", history[i]);
    }
    fclose(fp);
}

/* add a new command to history */
void add_history(const char *cmd) {
    if (cmd == NULL || *cmd == '\0') return;

    /* skip if same as last command */
    if (history_count > 0 && strcmp(history[history_count - 1], cmd) == 0) {
        return;
    }

    if (history_count < MAX_HISTORY) {
        history[history_count++] = strdup(cmd);
    } else {
        /* remove oldest entry */
        free(history[0]);
        for (int i = 1; i < MAX_HISTORY; i++) {
            history[i - 1] = history[i];
        }
        history[MAX_HISTORY - 1] = strdup(cmd);
    }

    save_history();
}

/* builtin log: print history */
int builtin_log(int argc, char **argv, char *output_file, int append) {
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

    /* Existing log logic starts here */
/* ############## LLM Generated Code Ends ################ */
    if (argc > 1 && strcmp(argv[1], "purge") == 0) {
        for (int i = 0; i < history_count; i++) {
            free(history[i]);
            history[i] = NULL;
        }
        history_count = 0;

        char path[4097];
        get_history_path(path, sizeof(path));
        FILE *fp = fopen(path, "w"); 
        if (fp) {
            fclose(fp);
        }
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "execute") == 0 ) {
        int index = atoi(argv[2]);
        if (index < 1 || index > history_count) {
            fprintf(stderr, "log: invalid index %s\n", argv[2]);

            if (saved_stdout >= 0) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            return 0;
        }
        const char *cmd = history[history_count-index];
        
        // Always just output the command - don't execute it
        // This prevents issues when log execute is used in pipelines
        printf("%s\n", cmd);
        
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        return 0;
    }
    for (int i = 0; i < history_count; i++) {
        printf("%s\n", history[i]);
    }
    
    /* Restore stdout */
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    
    return 0;
}
/* ############## LLM Generated Code Ends ################ */
