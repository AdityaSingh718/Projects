#ifndef SHELL_H
#define SHELL_H

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "A3.h"
#include "B1.h"
#include "B2.h"
#include "B3.h"
#include "C.h"
#include "E1.h"
#include "E2.h"
#include "E3.h"

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
