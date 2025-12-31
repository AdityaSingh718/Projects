#ifndef E2_H
#define E2_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>

int builtin_ping(int argc, char **argv, char *output_file, int append);

#endif
