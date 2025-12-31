#ifndef SIGNALS_H
#define SIGNALS_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>
#include "prompt.h"

// Global variables for tracking foreground process
extern pid_t foreground_pid;
extern char *foreground_cmd;

// Signal handler functions
void sigint_handler(int sig);
void sigtstp_handler(int sig);
void setup_signal_handlers(void);
void set_foreground_process(pid_t pid, const char *cmd);
void clear_foreground_process(void);
int check_eof(char *input);
void cleanup_and_exit(void);

#endif
