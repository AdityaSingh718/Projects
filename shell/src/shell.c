#include "../include/shell.h"
#include "../include/E4.h"

/* ############## LLM Generated Code Begins ################ */
/* Global flag to track if log command was run */
static int logf;

/* Background job management */
static struct background_job bg_jobs[MAX_BACKGROUND_JOBS];
static int next_job_number = 1;

/* Expose background jobs for activities command */
struct background_job *get_background_jobs(void) {
    return bg_jobs;
}

/* Cleanup terminated jobs for activities command */
void cleanup_terminated_jobs(void) {
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (bg_jobs[i].active) {
            int status;
            pid_t result = waitpid(bg_jobs[i].pid, &status, WNOHANG);
            if (result == bg_jobs[i].pid || (result == -1 && errno == ECHILD)) {
                // Process no longer exists - clean it up silently
                free(bg_jobs[i].command_name);
                bg_jobs[i].active = 0;
            }
        }
    }
}

/* Add a background job */
static void add_background_job(pid_t pid, const char *cmd_name) {
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (!bg_jobs[i].active) {
            bg_jobs[i].pid = pid;
            bg_jobs[i].job_number = next_job_number++;
            bg_jobs[i].command_name = strdup(cmd_name);
            bg_jobs[i].active = 1;
            printf("[%d] %d\n", bg_jobs[i].job_number, pid);
            break;
        }
    }
}

/* Check for completed background jobs */
static void check_background_jobs(void) {
    for (int i = 0; i < MAX_BACKGROUND_JOBS; i++) {
        if (bg_jobs[i].active) {
            int status;
            pid_t result = waitpid(bg_jobs[i].pid, &status, WNOHANG);
            if (result == bg_jobs[i].pid) {
                // Process completed
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    printf("%s with pid %d exited normally\n", 
                           bg_jobs[i].command_name, bg_jobs[i].pid);
                } else {
                    printf("%s with pid %d exited abnormally\n", 
                           bg_jobs[i].command_name, bg_jobs[i].pid);
                }
                free(bg_jobs[i].command_name);
                bg_jobs[i].active = 0;
            } else if (result == -1 && errno == ECHILD) {
                // Process no longer exists
                printf("%s with pid %d exited abnormally\n", 
                       bg_jobs[i].command_name, bg_jobs[i].pid);
                free(bg_jobs[i].command_name);
                bg_jobs[i].active = 0;
            }
        }
    }
}

/* Forward declaration */
int exec_node(struct node *n);

/* Helper function to flatten pipeline into a linear array */
static void flatten_pipeline(struct node *n, struct node ***commands, size_t *count) {
    if (n->type == NODE_ATOMIC) {
        *commands = realloc(*commands, (*count + 1) * sizeof(struct node *));
        (*commands)[*count] = n;
        (*count)++;
    } else if (n->type == NODE_CMD_GROUP) {
        for (size_t i = 0; i < n->child_count; i++) {
            flatten_pipeline(n->children[i], commands, count);
        }
    }
}

/* Execute an atomic command */
static int exec_atomic(struct node *n) {
    if (n->argc == 0) {
        /* no command, just redirection maybe → ignore */
        return 0;
    }
    
    // Check if this command should run in background
    if (n->background) {
        // Execute in background
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return -1;
        }
        
        if (pid == 0) {
            // Child process for background execution
            // Put background process in its own process group to isolate from signals
            setpgid(0, 0);
            
            // Redirect stdin to /dev/null to prevent terminal input access
            int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd >= 0) {
                dup2(null_fd, STDIN_FILENO);
                close(null_fd);
            }
            
            // Execute the command normally (without background flag)
            struct node temp_node = *n;
            temp_node.background = 0;  // Clear background flag for actual execution
            
            if (strcmp(temp_node.argv[0], "hop") == 0) {
                int result = builtin_hop(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else if (strcmp(temp_node.argv[0], "reveal") == 0) {
                int result = builtin_reveal(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else if(strcmp(temp_node.argv[0],"log")==0){
                int result = builtin_log(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else if (strcmp(temp_node.argv[0], "activities") == 0) {
                int result = builtin_activities(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else if (strcmp(temp_node.argv[0], "ping") == 0) {
                int result = builtin_ping(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else if (strcmp(temp_node.argv[0], "fg") == 0) {
                int result = builtin_fg(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else if (strcmp(temp_node.argv[0], "bg") == 0) {
                int result = builtin_bg(temp_node.argc, temp_node.argv, temp_node.output, temp_node.append);
                _exit(result == 0 ? 0 : 1);
            }
            else {
                int result = execute_command(temp_node.argc, temp_node.argv, temp_node.input, temp_node.output, temp_node.append);
                _exit(result);
            }
        } else {
            // Parent process - add to background jobs
            // Build full command string from argv
            char *full_cmd = malloc(1024);
            full_cmd[0] = '\0';
            for (size_t j = 0; j < n->argc; j++) {
                if (j > 0) strcat(full_cmd, " ");
                strcat(full_cmd, n->argv[j]);
            }
            strcat(full_cmd, " &");  // Add the & to show it's a background job
            add_background_job(pid, full_cmd);
            free(full_cmd);
            return 0;  // Background process started successfully
        }
    }
    
    // Regular foreground execution
    if (strcmp(n->argv[0], "hop") == 0) {
        return builtin_hop(n->argc, n->argv, n->output, n->append);
    }
    else if (strcmp(n->argv[0], "reveal") == 0) {
        return builtin_reveal(n->argc, n->argv, n->output, n->append);
    }
    else if(strcmp(n->argv[0],"log")==0){
        logf = 1; 
        return builtin_log(n->argc, n->argv, n->output, n->append);
    }
    else if (strcmp(n->argv[0], "activities") == 0) {
        return builtin_activities(n->argc, n->argv, n->output, n->append);
    }
    else if (strcmp(n->argv[0], "ping") == 0) {
        return builtin_ping(n->argc, n->argv, n->output, n->append);
    }
    else if (strcmp(n->argv[0], "fg") == 0) {
        return builtin_fg(n->argc, n->argv, n->output, n->append);
    }
    else if (strcmp(n->argv[0], "bg") == 0) {
        return builtin_bg(n->argc, n->argv, n->output, n->append);
    }
    else return execute_command(n->argc, n->argv, n->input, n->output, n->append);
}

/* Execute a pipeline or command group */
static int exec_cmd_group(struct node *n) {
    if (n->child_count == 1 && n->children[0]->type == NODE_ATOMIC) {
        return exec_node(n->children[0]);
    }
    
    // Check if this pipeline should run in background
    if (n->background) {
        // Execute entire pipeline in background
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return -1;
        }
        
        if (pid == 0) {
            // Child process for background execution
            // Put background process in its own process group to isolate from signals
            setpgid(0, 0);
            
            // Redirect stdin to /dev/null to prevent terminal input access
            int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd >= 0) {
                dup2(null_fd, STDIN_FILENO);
                close(null_fd);
            }
            
            // Execute the pipeline normally (without background flag)
            struct node temp_node = *n;
            temp_node.background = 0;  // Clear background flag for actual execution
            int result = exec_cmd_group(&temp_node);
            _exit(result);
        } else {
            // Parent process - add to background jobs
            // For pipelines, use the first command name
            struct node **commands = NULL;
            size_t cmd_count = 0;
            flatten_pipeline(n, &commands, &cmd_count);
            char *cmd_name = strdup("pipeline");
            if (cmd_count > 0 && commands[0]->argc > 0) {
                // Build full command string for first command in pipeline
                free(cmd_name);
                cmd_name = malloc(1024);
                cmd_name[0] = '\0';
                for (size_t j = 0; j < commands[0]->argc; j++) {
                    if (j > 0) strcat(cmd_name, " ");
                    strcat(cmd_name, commands[0]->argv[j]);
                }
                strcat(cmd_name, " &");  // Add the & to show it's a background job
            }
            free(commands);
            add_background_job(pid, cmd_name);
            free(cmd_name);
            return 0;  // Background process started successfully
        }
    }
    
    // Flatten the pipeline into a linear array
    struct node **commands = NULL;
    size_t cmd_count = 0;
    flatten_pipeline(n, &commands, &cmd_count);
    
    if (cmd_count == 1) {
        int result = exec_node(commands[0]);
        free(commands);
        return result;
    }
    
    // Execute pipeline
    int num_pipes = cmd_count - 1;
    int pipes[num_pipes][2];  // Array of pipe file descriptors
    pid_t pids[cmd_count];  // Array to store child PIDs
    
    // Create all pipes
    for (int i = 0; i < num_pipes; i++) {
        if (pipe(pipes[i]) < 0) {
            perror("pipe");
            free(commands);
            return -1;
        }
    }
    
    // Fork and execute each command in the pipeline
    for (size_t i = 0; i < cmd_count; i++) {
        pids[i] = fork();
        if (pids[i] < 0) {
            perror("fork");
            free(commands);
            return -1;
        }
        
        if (pids[i] == 0) {
            // Child process
            
            // Handle input redirection for first command
            if (i == 0 && commands[i]->input) {
                int fd = open(commands[i]->input, O_RDONLY);
                if (fd < 0) {
                    fprintf(stderr, "Error opening %s: %s\n", commands[i]->input, strerror(errno));
                    _exit(1);
                }
                dup2(fd, STDIN_FILENO);
                close(fd);
            } else if (i > 0) {
                // Not first command - get input from previous pipe
                dup2(pipes[i-1][0], STDIN_FILENO);
            }
            
            // Handle output redirection for last command
            if (i == cmd_count - 1 && commands[i]->output) {
                int flags = O_WRONLY | O_CREAT;
                if (commands[i]->append) {
                    flags |= O_APPEND;
                } else {
                    flags |= O_TRUNC;
                }
                int fd = open(commands[i]->output, flags, 0644);
                if (fd < 0) {
                    fprintf(stderr, "Error opening %s: %s\n", commands[i]->output, strerror(errno));
                    _exit(1);
                }
                dup2(fd, STDOUT_FILENO);
                close(fd);
            } else if (i < cmd_count - 1) {
                // Not last command - send output to next pipe
                dup2(pipes[i][1], STDOUT_FILENO);
            }
            
            // Close all pipe file descriptors in child
            for (int j = 0; j < num_pipes; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            
            // Execute the command
            if (commands[i]->argc > 0) {
                if (strcmp(commands[i]->argv[0], "hop") == 0) {
                    int result = builtin_hop(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else if (strcmp(commands[i]->argv[0], "reveal") == 0) {
                    int result = builtin_reveal(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else if (strcmp(commands[i]->argv[0], "log") == 0) {
                    int result = builtin_log(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else if (strcmp(commands[i]->argv[0], "activities") == 0) {
                    int result = builtin_activities(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else if (strcmp(commands[i]->argv[0], "ping") == 0) {
                    int result = builtin_ping(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else if (strcmp(commands[i]->argv[0], "fg") == 0) {
                    int result = builtin_fg(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else if (strcmp(commands[i]->argv[0], "bg") == 0) {
                    int result = builtin_bg(commands[i]->argc, commands[i]->argv, NULL, 0);
                    _exit(result == 0 ? 0 : 1);
                } else {
                    // External command
                    char **exec_argv = malloc((commands[i]->argc + 1) * sizeof(char *));
                    for (size_t k = 0; k < commands[i]->argc; k++) {
                        exec_argv[k] = commands[i]->argv[k];
                    }
                    exec_argv[commands[i]->argc] = NULL;
                    execvp(exec_argv[0], exec_argv);
                    printf("Command not found!\n");
                    free(exec_argv);
                    _exit(127);
                }
            }
            _exit(1);  // Should not reach here normally
        }
    }
    
    // Parent process: close all pipe file descriptors
    for (int i = 0; i < num_pipes; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }
    
    // Wait for all child processes
    int last_exit_status = 0;
    
    // Set the last process in pipeline as foreground process for signal handling
    if (cmd_count > 0) {
        const char *last_cmd = "pipeline";
        if (commands[cmd_count-1]->argc > 0) {
            last_cmd = commands[cmd_count-1]->argv[0];
        }
        set_foreground_process(pids[cmd_count-1], last_cmd);
    }
    
    for (size_t i = 0; i < cmd_count; i++) {
        int status;
        pid_t result = waitpid(pids[i], &status, WUNTRACED);
        if (result < 0) {
            perror("waitpid");
        } else {
            // Check if the last process in pipeline was stopped
            if (i == cmd_count - 1 && WIFSTOPPED(status)) {
                // Last process was stopped - it's now in background
                return 0;  // Don't clear foreground process, signal handler did it
            }
            
            if (i == cmd_count - 1) {  // Return exit status of last command
                if (WIFEXITED(status)) {
                    last_exit_status = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    last_exit_status = 128 + WTERMSIG(status);
                }
            }
        }
    }
    
    // Clear foreground process if we get here (normal completion)
    clear_foreground_process();
    
    free(commands);
    return last_exit_status;
}

/* Execute a shell command (sequences, background) */
static int exec_shell_cmd(struct node *n) {
    int last_result = 0;
    
    for (size_t i = 0; i < n->child_count; i++) {
        struct node *child = n->children[i];
        
        // Check if this specific command should run in background
        if (child->background) {
            // Execute this command in background
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                return -1;
            }
            
            if (pid == 0) {
                // Child process for background execution
                // Put background process in its own process group to isolate from signals
                setpgid(0, 0);
                
                // Redirect stdin to /dev/null to prevent terminal input access
                int null_fd = open("/dev/null", O_RDONLY);
                if (null_fd >= 0) {
                    dup2(null_fd, STDIN_FILENO);
                    close(null_fd);
                }
                
                // Execute the command (clear background flag to avoid double-forking)
                struct node temp_node = *child;
                temp_node.background = 0;
                int result = exec_node(&temp_node);
                _exit(result);
            } else {
                // Parent process - add to background jobs
                char *cmd_name = "unknown";
                char *allocated_cmd = NULL;
                if (child->type == NODE_ATOMIC && child->argc > 0) {
                    // Build full command string from argv
                    allocated_cmd = malloc(1024);
                    allocated_cmd[0] = '\0';
                    for (size_t j = 0; j < child->argc; j++) {
                        if (j > 0) strcat(allocated_cmd, " ");
                        strcat(allocated_cmd, child->argv[j]);
                    }
                    strcat(allocated_cmd, " &");  // Add the & to show it's a background job
                    cmd_name = allocated_cmd;
                } else if (child->type == NODE_CMD_GROUP) {
                    // For pipelines, use the first command name
                    struct node **commands = NULL;
                    size_t cmd_count = 0;
                    flatten_pipeline(child, &commands, &cmd_count);
                    if (cmd_count > 0 && commands[0]->argc > 0) {
                        allocated_cmd = malloc(1024);
                        allocated_cmd[0] = '\0';
                        for (size_t j = 0; j < commands[0]->argc; j++) {
                            if (j > 0) strcat(allocated_cmd, " ");
                            strcat(allocated_cmd, commands[0]->argv[j]);
                        }
                        strcat(allocated_cmd, " &");  // Add the & to show it's a background job
                        cmd_name = allocated_cmd;
                    }
                    free(commands);
                }
                add_background_job(pid, cmd_name);
                if (allocated_cmd) free(allocated_cmd);
                // Don't wait for background jobs, continue immediately
            }
        } else {
            // Execute sequentially (wait for completion)
            last_result = exec_node(child);
            // Continue to next command even if this one failed
        }
    }
    return last_result;
}

/* Dispatcher */
int exec_node(struct node *n) {
    if (!n) return -1;
    switch (n->type) {
        case NODE_ATOMIC:
            return exec_atomic(n);
        case NODE_CMD_GROUP:
            return exec_cmd_group(n);
        case NODE_SHELL_CMD:
            return exec_shell_cmd(n);
        default:
            fprintf(stderr, "Unknown node type %d\n", n->type);
            return -1;
    }
}
/* ############## LLM Generated Code Ends ################ */

int main() {
    init_homedir();
    load_history();
    
    // Setup signal handlers for Ctrl+C and Ctrl+Z
    setup_signal_handlers();
    
    while (1) {
        // Check for completed background jobs before showing prompt
        check_background_jobs();
        
        shellprompt();
        char* input = read_input();
        
        // Check for EOF (Ctrl+D)
        if (check_eof(input)) {
            cleanup_and_exit();
        }
        
        if (strlen(input) == 0) {
            continue;
        }
        
        f = 1,logf=0;
        
        // Check for completed background jobs before executing the new command
        check_background_jobs();
        
        struct token_list tokens = tokenize(input);
        struct parser parser = {&tokens, 0};
        struct node *ast = parse_shell_cmd(&parser);

        if (f == 0) {
            printf("Invalid Syntax!\n");
            for (size_t i = 0; i < tokens.count; i++) {
                free(tokens.tokens[i]);
            }
            free(tokens.tokens);
            add_history(input);
            continue;
        } 
        exec_node(ast);

        // Check for completed background jobs after command execution
        check_background_jobs();

        for (size_t i = 0; i < tokens.count; i++) {
            free(tokens.tokens[i]);
        }
        free(tokens.tokens);
        if(!logf) add_history(input);
    }
    return 0;
}
