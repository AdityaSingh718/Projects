#ifndef BUILTIN_REVEAL_H
#define BUILTIN_REVEAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <fcntl.h>
#include "prompt.h"
#include "builtin_hop.h"

int builtin_reveal(int argc, char **argv, char *output_file, int append);

#endif 
