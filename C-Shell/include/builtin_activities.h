#ifndef BUILTIN_ACTIVITIES_H
#define BUILTIN_ACTIVITIES_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>

int builtin_activities(int argc, char **argv, char *output_file, int append);

#endif
