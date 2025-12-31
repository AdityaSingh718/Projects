#include "../include/builtin_reveal.h"
/* ############## LLM Generated Code Begins ################ */
/* Resolve special paths like hop does */
static const char *resolve_path(const char *arg, char *buf, size_t buflen) {
    if (!arg) {
        return "."; /* no path given */
    }

    if (strcmp(arg, "~") == 0) {
        strncpy(buf, homedir, buflen);
        return buf;
    } else if (strcmp(arg, ".") == 0) {
        return ".";
    } else if (strcmp(arg, "..") == 0) {
        return "..";
    } else if (strcmp(arg, "-") == 0) {
        if (prev_cwd[0] == '\0') {
            return NULL; /* indicate invalid path */
        }
        strncpy(buf, prev_cwd, buflen);
        return buf;
    }
    /* default: treat as literal path */
    return arg;
}
static int cmpstr(const void *a, const void *b) {
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sa, sb);
}
int builtin_reveal(int argc, char **argv, char *output_file, int append) {
    
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

    /* Existing reveal logic starts here */
    int show_all = 0;
    int long_list = 0;
    const char *path = NULL;
    char resolved[4097];
    int path_count = 0;

    /* Parse flags */
    for (int i = 1; i < argc; i++) {
        int fl=0;
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fl=1;
            int os=show_all,ol=long_list;
            for (int j = 1; argv[i][j] != '\0'; j++) {
                if (argv[i][j] == 'a') {
                    show_all = 1;
                } else if (argv[i][j] == 'l') {
                    long_list = 1;
                } else {
                    fl=0,show_all=os,long_list=ol;
                    break;
                }
            }
        } 
        if(!fl) {
            /* treat as path */
            path_count++;
            if (path_count > 1) {
                /* Too many path arguments */
                printf("reveal: Invalid Syntax!\n");
                if (saved_stdout >= 0) {
                    dup2(saved_stdout, STDOUT_FILENO);
                    close(saved_stdout);
                }
                return 0;
            }
            path = resolve_path(argv[i], resolved, sizeof(resolved));
            if (path == NULL) {
                /* Invalid path (e.g., "-" with no prev_cwd) */
                printf("No such directory!\n");
                if (saved_stdout >= 0) {
                    dup2(saved_stdout, STDOUT_FILENO);
                    close(saved_stdout);
                }
                return 0;
            }
        }
    }

    if (!path) {
        path = ".";
    }

    DIR *dir = opendir(path);
    if (!dir) {
        printf("No such directory!\n");
        return 0;
    }

    size_t cap = 64;
    size_t count = 0;
    char **entries = malloc(cap * sizeof(char *));
    if (!entries) {
        closedir(dir);
        perror("malloc");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!show_all && entry->d_name[0] == '.') {
            continue;
        }

        if (count == cap) {
            cap *= 2;
            char **tmp = realloc(entries, cap * sizeof(char *));
            if (!tmp) {
                perror("realloc");
                /* free allocated so far */
                for (size_t j = 0; j < count; j++) free(entries[j]);
                free(entries);
                closedir(dir);
                return -1;
            }
            entries = tmp;
        }

        entries[count] = strdup(entry->d_name);
        if (!entries[count]) {
            perror("strdup");
            for (size_t j = 0; j < count; j++) free(entries[j]);
            free(entries);
            closedir(dir);
            return -1;
        }
        count++;
    }
    closedir(dir);

    /* sort entries */
    qsort(entries, count, sizeof(char *), cmpstr);

    /* print */
    for (size_t i = 0; i < count; i++) {
        if (long_list) {
            printf("%s\n", entries[i]);
        } else {
            printf("%s", entries[i]);
            if (i + 1 < count) printf(" ");
        }
        free(entries[i]);
    }
    if (!long_list) printf("\n");

    free(entries);
    
    /* Restore stdout */
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    
    return 0;
}
/* ############## LLM Generated Code Ends ################ */