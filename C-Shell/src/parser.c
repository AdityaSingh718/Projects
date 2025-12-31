#include "../include/parser.h"
int f=1;

int notname(const char *tok) {
    if (!tok) return 0;
    return strcmp(tok, "|") == 0 || strcmp(tok, "&") == 0 ||
           strcmp(tok, ";") == 0 || strcmp(tok, "<") == 0 ||
           strcmp(tok, ">") == 0 || strcmp(tok, ">>") == 0;
}

/* ############## LLM Generated Code Begins ################ */
static void add_token(struct token_list *result, const char *start, size_t len) {
    char *tok = malloc(len + 1);
    if (!tok) _exit(1);
    memcpy(tok, start, len);
    tok[len] = '\0';
    result->tokens = realloc(result->tokens, (result->count + 1) * sizeof(char *));
    if (!result->tokens) _exit(1);
    result->tokens[result->count++] = tok;
}

struct token_list tokenize(const char *line) {
    struct token_list result = { NULL, 0 };
    const char *p = line;

    while (*p) {
        /* skip whitespace */
        if (isspace((unsigned char)*p)) {
            p++;
            continue;
        }

        /* handle multi-char operators */
        if (*p == '>' && *(p+1) == '>') {
            add_token(&result, p, 2);
            p += 2;
            continue;
        }
        if (*p == '<' && *(p+1) == '<') {
            add_token(&result, p, 2);
            p += 2;
            continue;
        }

        /* handle single-char operators */
        if (*p == '|' || *p == '&' || *p == ';' || *p == '<' || *p == '>') {
            add_token(&result, p, 1);
            p++;
            continue;
        }

        /* otherwise it's a "name" (command or argument) */
        const char *start = p;
        while (*p && !isspace((unsigned char)*p)) {
            /* Stop at operators - they should be separate tokens */
            if(*p == '|' || *p == '&' || *p == ';' || *p == '<' || *p == '>') {
                break;
            }
            p++;
        }
        add_token(&result, start, (size_t)(p - start));
    }

    return result;
}

static const char *peek(struct parser *p) {
    if (p->pos < p->tokens->count)
        return p->tokens->tokens[p->pos];
    return NULL;
}

static const char *consume(struct parser *p) {
    if (p->pos < p->tokens->count)
        return p->tokens->tokens[p->pos++];
    return NULL;
}

static int accept(struct parser *p, const char *tok) {
    const char *cur = peek(p);
    if (cur && strcmp(cur, tok) == 0) {
        consume(p);
        return 1;
    }
    return 0;
}

static struct node *parse_atomic(struct parser *p) {
    const char *tok = peek(p);
    if (!tok) return NULL;

    if (notname(tok)) {
        f = 0;
        return NULL;
    }

    struct node *n = calloc(1, sizeof(*n));
    n->type = NODE_ATOMIC;

    while ((tok = peek(p))) {
        if (strcmp(tok, "|") == 0 || strcmp(tok, "&") == 0 ||
            strcmp(tok, ";") == 0)
            break;

        if (strcmp(tok, "<") == 0) {
            consume(p);
            const char *input = consume(p);
            if (input == NULL || notname(input)) {
                f = 0;
                free(n);
                return NULL;
            }
            // Check if input file exists
            if (access(input, R_OK) != 0) {
                printf("No such file or directory\n");
                f = 0;
                free(n);
                return NULL;
            }
            if (n->input) free(n->input);
            n->input = strdup(input);
            continue;
        }
        if (strcmp(tok, ">") == 0 || strcmp(tok, ">>") == 0) {
            n->append = (strcmp(tok, ">>") == 0);
            consume(p);
            const char *output = consume(p);
            if (output == NULL || notname(output)) {
                f = 0;
                free(n);
                return NULL;
            }
            // Check if output file can be created/written
            int test_fd = open(output, O_WRONLY | O_CREAT, 0644);
            if (test_fd < 0) {
                if (errno == EACCES || errno == EPERM) {
                    printf("Unable to create file for writing\n");
                } else {
                    printf("Error opening %s: %s\n", output, strerror(errno));
                }
                f = 0;
                free(n);
                return NULL;
            }
            close(test_fd);
            if (n->output) free(n->output);
            n->output = strdup(output);
            continue;
        }
        
        /* otherwise treat as a name/argument */
        n->argv = realloc(n->argv, (n->argc + 1) * sizeof(char *));
        n->argv[n->argc++] = strdup(consume(p));
    }
    return n;
}

static struct node *parse_cmd_group(struct parser *p) {
    struct node *left = parse_atomic(p);
    if (!left) {
        if (peek(p)) f = 0;
        return NULL;
    }

    while (accept(p, "|")) {
        struct node *right = parse_atomic(p);
        if (!right) {
            f = 0;
            return NULL; 
        }
        struct node *pipe_node = calloc(1, sizeof(*pipe_node));
        pipe_node->type = NODE_CMD_GROUP;
        pipe_node->children = realloc(pipe_node->children,
                                      (pipe_node->child_count + 1) * sizeof(struct node *));
        pipe_node->children[pipe_node->child_count++] = left;
        pipe_node->children = realloc(pipe_node->children,
                                      (pipe_node->child_count + 1) * sizeof(struct node *));
        pipe_node->children[pipe_node->child_count++] = right;
        left = pipe_node;
    }
    return left;
}

struct node *parse_shell_cmd(struct parser *p) {
    struct node *first_cmd = parse_cmd_group(p);
    if (!first_cmd) {
        if (peek(p)) f = 0;
        return NULL;
    }

    // Check if there are sequence operators
    if (!peek(p) || (strcmp(peek(p), ";") != 0 && strcmp(peek(p), "&") != 0)) {
        // Single command, check if it ends with &
        if (peek(p) && strcmp(peek(p), "&") == 0) {
            consume(p);
            first_cmd->background = 1;
        }
        return first_cmd;
    }

    // Multiple commands - create a shell command node to hold the sequence
    struct node *shell_node = calloc(1, sizeof(*shell_node));
    shell_node->type = NODE_SHELL_CMD;

    // Add the first command
    shell_node->children = realloc(shell_node->children, 
                                   (shell_node->child_count + 1) * sizeof(struct node *));
    shell_node->children[shell_node->child_count++] = first_cmd;
    
    while (peek(p) && (strcmp(peek(p), ";") == 0 || strcmp(peek(p), "&") == 0)) {
        int background = (strcmp(peek(p), "&") == 0);
        consume(p);

        // If we hit & at the end of input, set background on the last command
        if (!peek(p)) { 
            if (background) {
                // Set background flag on the last command added
                shell_node->children[shell_node->child_count - 1]->background = 1;
                break;
            }
            f = 0;
            return NULL;
        }

        // Set background flag on the previous command if & was encountered
        if (background) {
            shell_node->children[shell_node->child_count - 1]->background = 1;
        }

        struct node *next_cmd = parse_cmd_group(p);
        if (!next_cmd) {
            f = 0;
            return NULL;
        }

        // Add the next command to the sequence
        shell_node->children = realloc(shell_node->children,
                                       (shell_node->child_count + 1) * sizeof(struct node *));
        shell_node->children[shell_node->child_count++] = next_cmd;
    }

    if (peek(p)) { 
        f = 0;
    }

    return shell_node;
}
/* ############## LLM Generated Code Ends ################ */



