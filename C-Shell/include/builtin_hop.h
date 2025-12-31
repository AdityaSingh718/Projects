#ifndef BUILTIN_HOP_H
#define BUILTIN_HOP_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/param.h>
#include "prompt.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern char prev_cwd[4097];

int builtin_hop(int argc, char **argv, char *output_file, int append);

#endif 
