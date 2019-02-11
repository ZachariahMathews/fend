#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <glob.h>
#include <signal.h>
#include <errno.h>
#include <map>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>

using namespace std;

#define OP_READ 0
#define OP_WRITE 1
#define OP_EXEC 2

void removeNewLine(char *str)
{
    str[strcspn(str, "\n")] = 0;
}

map<string, string> buildPermissionsMap(char *configFilePath)
{
    map<string, string> permissionsMap;

    FILE *stream = fopen(configFilePath, "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    while ((nread = getline(&line, &len, stream)) != -1)
    {
        if (nread > 1)
        {
            char absolutePath[4096];
            int idx = 0;
            glob_t globbuf;

            char *permissions = strtok(line, " \t");
            char *path = strtok(NULL, " ");
            removeNewLine(permissions);
            removeNewLine(path);

            realpath(path, absolutePath);
            glob(absolutePath, GLOB_PERIOD, NULL, &globbuf);

            for (int i = 0; i < globbuf.gl_pathc; i++)
            {
                string matchedPath = globbuf.gl_pathv[i];
                if (permissionsMap.find(matchedPath) != permissionsMap.end())
                {
                    permissionsMap.erase(matchedPath);
                }
                permissionsMap.insert({matchedPath, string(permissions)});
            }
            globfree(&globbuf);
        }
    }

    return permissionsMap;
}

bool isOperationAllowed(string filePermissions, int operation)
{
    return filePermissions[operation] == '1';
}

void restrictAccess(user_regs_struct regs, long childPid)
{
    regs.orig_rax = -1;
    ptrace(PTRACE_SETREGS, childPid, 0, &regs);
    ptrace(PTRACE_SYSCALL, childPid, NULL, NULL);
    waitpid(childPid, 0, 0);
    regs.rax = -EACCES;
    ptrace(PTRACE_SETREGS, childPid, NULL, &regs);
}

int main(int argc, char **argv)
{
    char *configFilePath = NULL;
    char **args;
    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1)
    {
        switch (opt)
        {
        case 'c':
            configFilePath = optarg;
            args = new char *[argc - 3];
            for (int i = 3; i < argc; i++)
            {
                args[i - 3] = argv[i];
                printf(" ");
            }
            args[argc - 3] = NULL;
            break;
            break;
        default:
            printf("Invalid options");
            return 1;
        }
    }

    if (configFilePath == NULL)
    {
        if (access("./fendrc", F_OK) == 0)
        {
            configFilePath = "./fendrc";
        }
        else
        {
            char *homePath = getenv("HOME");
            configFilePath = (char *)malloc(strlen(homePath) + strlen("/fendrc") + 1);
            strcpy(configFilePath, homePath);
            strcat(configFilePath, "/fendrc");
            if (access(configFilePath, F_OK) != 0)
            {
                printf("Must provide a config file.\n");
                return 1;
            }
        }

        args = new char *[argc - 1];
        for (int i = 1; i < argc; i++)
        {
            args[i - 1] = argv[i];
        }
        args[argc - 1] = NULL;
    }
    map<string, string> permissionsMap = buildPermissionsMap(configFilePath);

    pid_t childPid = fork();
    if (childPid == 0)
    {
        printf("in child");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(args[0], args);
        printf("All good");
    }
    else
    {
        int toggle = 0;
        while (1)
        {
            int wstatus;
            wait(&wstatus);
            if (WIFEXITED(wstatus))
                break;
            struct user_regs_struct regs;
            long sysCall = ptrace(PTRACE_PEEKUSER, childPid, 8 * ORIG_RAX, NULL);
            switch (sysCall)
            {
            case SYS_openat:
            case SYS_open:
                if (toggle == 0)
                {
                    toggle = 1;
                    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
                    int offset = 0;
                    if (sysCall == SYS_open)
                        offset = RDI;
                    else
                        offset = RSI;
                    long childAddress = ptrace(PTRACE_PEEKUSER, childPid, sizeof(long) * offset, 0);

                    char buffer[PATH_MAX];
                    char *laddr = buffer;
                    string filePath = "";
                    for (int i = 0; i < PATH_MAX / sizeof(long); i++)
                    {
                        char *val = (char *)ptrace(PTRACE_PEEKTEXT, childPid, childAddress + i * 8, NULL);
                        memcpy(laddr, (char *)&val, sizeof(long));
                        laddr += sizeof(long);
                    }
                    buffer[PATH_MAX] = '\0';

                    char absolutePath[PATH_MAX];
                    realpath(buffer, absolutePath);

                    long mode = regs.rdx;
                    map<string, string>::iterator itr = permissionsMap.find(absolutePath);
                    if (itr != permissionsMap.end())
                    {
                        if (mode == O_RDONLY && !isOperationAllowed(itr->second, OP_READ))
                        {
                            restrictAccess(regs, childPid);
                        }
                        else if (mode == O_WRONLY && !isOperationAllowed(itr->second, OP_WRITE))
                        {
                            restrictAccess(regs, childPid);
                        }
                        else if (mode == O_RDWR && (!isOperationAllowed(itr->second, OP_WRITE) || !isOperationAllowed(itr->second, OP_READ)))
                        {
                            restrictAccess(regs, childPid);
                        }
                    }
                }
                else
                {
                    toggle = 0;
                }
                break;
            case SYS_execve:
                if (args[1] == NULL)
                {
                    char absolutePath[PATH_MAX];
                    realpath(args[0], absolutePath);
                    map<string, string>::iterator itr = permissionsMap.find(absolutePath);
                    if (itr != permissionsMap.end())
                    {
                        if (!isOperationAllowed(itr->second, OP_EXEC))
                        {
                            printf("Permission denied");
                            restrictAccess(regs, childPid);
                        }
                    }
                }
                break;
            case SYS_rename:
                printf("In rename");
                char absolutePath[PATH_MAX];
                printf("%s %s %s", args[0], args[1], args[2]);
                realpath(args[1], absolutePath);
                map<string, string>::iterator itr = permissionsMap.find(absolutePath);
                if (itr != permissionsMap.end())
                {
                    if (!isOperationAllowed(itr->second, OP_READ))
                    {
                        restrictAccess(regs, childPid);
                    }
                }
                break;
            }
            ptrace(PTRACE_SYSCALL, childPid, NULL, NULL);
        }
    }
}