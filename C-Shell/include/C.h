#ifndef C_H
#define C_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

int execute_command(int argc, char **argv, char *input_file, char *output_file, int append);

#endif 