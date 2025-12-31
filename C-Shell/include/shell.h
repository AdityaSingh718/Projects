#ifndef SHELL_H
#define SHELL_H

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "parser.h"
#include "builtin_hop.h"
#include "builtin_reveal.h"
#include "builtin_log.h"
#include "executor.h"
#include "builtin_activities.h"
#include "builtin_ping.h"
#include "signals.h"

// Background job management constants and structures
#define MAX_BACKGROUND_JOBS 100
struct background_job {
    pid_t pid;
    int job_number;
    char *command_name;
    int active;
};

// Function declarations
int exec_node(struct node *n);

// Background job functions (exposed for activities command)
extern struct background_job *get_background_jobs(void);
extern void cleanup_terminated_jobs(void);

// Main function declaration
int main(void);

#endif // SHELL_H 
