#ifndef B2_H
#define B2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <fcntl.h>
#include "A1.h"
#include "B1.h"

int builtin_reveal(int argc, char **argv, char *output_file, int append);

#endif 
