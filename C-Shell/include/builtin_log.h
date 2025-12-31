#ifndef BUILTIN_LOG_H
#define BUILTIN_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/param.h>
#include <fcntl.h>
#include "parser.h"

#define HISTORY_FILE ".shellhistory"
#define MAX_HISTORY 15

// Function declarations
void load_history(void);
void add_history(const char *cmd);
int builtin_log(int argc, char **argv, char *output_file, int append);

#endif // BUILTIN_LOG_H