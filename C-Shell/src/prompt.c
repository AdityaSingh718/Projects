#include "../include/prompt.h"

char homedir[4097];

void init_homedir()
{
    if (getcwd(homedir, sizeof(homedir)) == NULL)
    {
        perror("getcwd");
    }
}

void shellprompt()
{
    /* ############## LLM Generated Code Begins ################ */
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL)
    {
        perror("getpwuid");
        return;
    }
    char hostname[4097];
    if (gethostname(hostname, sizeof(hostname)) != 0)
    {
        perror("gethostname");
        return;
    }
    char cwd[4097];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        perror("getcwd");
        return;
    }
    /* ############## LLM Generated Code Ends ################ */
    
    if (strncmp(cwd, homedir, strlen(homedir)) == 0)
    {
        if (strcmp(cwd, homedir) == 0)
        {
            printf("<%s@%s:~> ", pw->pw_name, hostname);
        }
        else
        {
            printf("<%s@%s:~%s> ", pw->pw_name, hostname, cwd + strlen(homedir));
        }
    }
    else
    {
        printf("<%s@%s:%s> ", pw->pw_name, hostname, cwd);
    }
    fflush(stdout);
}