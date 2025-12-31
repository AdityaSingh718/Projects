#ifndef E4_H
#define E4_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>

int builtin_fg(int argc, char **argv, char *output_file, int append);
int builtin_bg(int argc, char **argv, char *output_file, int append);

#endif
