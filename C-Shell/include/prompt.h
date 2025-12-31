#ifndef PROMPT_H
#define PROMPT_H

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>

extern char homedir[4097];

void init_homedir(void);
void shellprompt(void);

#endif 
