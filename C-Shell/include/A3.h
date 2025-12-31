#ifndef A3_H
#define A3_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "A2.h"

extern int f;
/* ############## LLM Generated Code Begins ################ */
enum node_type { 
    NODE_SHELL_CMD, 
    NODE_CMD_GROUP, 
    NODE_ATOMIC 
};

struct token_list {
    char **tokens;
    size_t count;
};

struct node {
    enum node_type type;
    char **argv;              /* for atomic commands */
    size_t argc;

    char *input;              /* < file */
    char *output;             /* > or >> file */
    int append;               /* 1 if >> */

    struct node **children;   /* for pipelines and sequences */
    size_t child_count;

    int background;           /* & at end */
};

struct parser {
    struct token_list *tokens;
    size_t pos;
};
/* ############## LLM Generated Code Ends ################ */
int notname(const char *tok);
struct token_list tokenize(const char *line);
struct node *parse_shell_cmd(struct parser *p);


#endif 
