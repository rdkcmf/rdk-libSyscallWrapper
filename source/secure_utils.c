#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdarg.h>
#include "rdk_debug.h"
#include <linux/limits.h>
#define MAX_LEN 128
#define MAX_PARAM 31 //including NULL terminator for list
#define CMD_SIZE 1024
#define PATH_SIZE 1024
#define BUF_SIZE 1024
#define STRINGSTR(sent,word) (strstr(sent, word) != NULL)
#define LOG_LIB "LOG.RDK.LIBSYSCALLWRAPPER"

char* path_finder(const char * arg)
{
    char* smd = (char*)calloc(PATH_MAX,sizeof(char));
    char cpath[PATH_MAX] = {'\0'};
    char* pathcpy = cpath;
    char* path = NULL;
    int n;
    /* Ignore if file is absolute or relative.
     */
    if ((arg[0] == '/') || (arg[0] == '.')) {
        n = snprintf(smd, PATH_MAX, "%s",arg);
        if(n>=PATH_MAX || n<0)
        {
            RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:PATH SIZE overflow:%s\n",__FUNCTION__,arg);
            fprintf(stderr, "%s:PATH SIZE overflow:%s\n", __FUNCTION__, arg);
            free(smd);
            return NULL;
        }
        struct stat fd;
        if (stat(smd, &fd) == 0) {
            return smd;
        } else{
            RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:PATH NOT FOUND for command:%s\n",__FUNCTION__,arg);
            fprintf(stderr, "%s:PATH NOT FOUND for command:%s\n", __FUNCTION__, arg);
            free(smd);
            return NULL;
        }
    }

    /* Copy path environment string and null terminate. */
    strncpy(cpath, getenv("PATH"), PATH_MAX-1)[PATH_MAX-1] = '\0';
    while ((path = strtok_r(pathcpy, ":", &pathcpy))) {
        if (path != NULL) {
            n = snprintf(smd, PATH_MAX, "%s/%s", path, arg);
            if(n>=PATH_MAX || n<0)
            {
                RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:PATH SIZE overflow:%s\n",__FUNCTION__,arg);
                //fprintf(stderr, "%s:PATH SIZE overflow:%s\n", __FUNCTION__, arg);
                free(smd);
                return NULL;
            }
            struct stat fd;
            if (stat(smd, &fd) == 0) {
                /* File exists in path, return absolute. */
                return smd;
            }
        }
    }

    /* No file found */
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:PATH NOT FOUND for command:%s\n",__FUNCTION__,arg);
        fprintf(stderr, "%s:PATH NOT FOUND for command:%s\n", __FUNCTION__, arg);
    free(smd);
    return NULL;
}
void free_arrmem2(char ** fmd_args)
{
    int i=0;
    if(fmd_args == NULL)
        {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:invalid arguments\n",__FUNCTION__);
        fprintf(stderr, "%s:invalid arguments\n", __FUNCTION__);
             return;
        }
    while(fmd_args[i] != NULL)
    {
        free(fmd_args[i++]);
    }
    free(fmd_args);
    return;
}

/*
 * The following SPC functions are taken from examples within the following
 * book:
 *      Secure Programming Cookbook for C and C++
 *      by John Viega; Matt Messier
 *      Published by O'Reilly Media, Inc., 2003
 *      ISBN: 9780596003944
 *      https://resources.oreilly.com/examples/9780596003944.git
 *
 * Permission to use is outlined in:
 *      https://resources.oreilly.com/examples/9780596003944/blob/master/README.md
 */

pid_t spc_fork(void) {
        pid_t childpid;

        if ((childpid = fork(  )) == -1) return -1;
        /* If this is the parent process, there's nothing more to do */
        if (childpid != 0) return childpid;
        /* This is the child process */
        return 0;
}
typedef struct {
        FILE  *read_fd;
        FILE  *write_fd;
        pid_t child_pid;
} SPC_PIPE;

SPC_PIPE *spc_popen(const char *path, char *const argv[], char *const envp[]) {
        int      stdin_pipe[2], stdout_pipe[2];
        SPC_PIPE *p;

        if (!(p = (SPC_PIPE *)malloc(sizeof(SPC_PIPE)))) return 0;
        p->read_fd = p->write_fd = 0;
        p->child_pid = -1;

        if (pipe(stdin_pipe) == -1) {
                free(p);
                return 0;
        }
        if (pipe(stdout_pipe) == -1) {
                close(stdin_pipe[1]);
                close(stdin_pipe[0]);
                free(p);
                return 0;
        }

        if (!(p->read_fd = fdopen(stdout_pipe[0], "r"))) {
                close(stdout_pipe[1]);
                close(stdout_pipe[0]);
                close(stdin_pipe[1]);
                close(stdin_pipe[0]);
                free(p);
                return 0;
        }
        if (!(p->write_fd = fdopen(stdin_pipe[1], "w"))) {
                fclose(p->read_fd);
                close(stdout_pipe[1]);
                close(stdin_pipe[1]);
                close(stdin_pipe[0]);
                free(p);
                return 0;
        }

        if ((p->child_pid = spc_fork(  )) == -1) {
                fclose(p->write_fd);
                fclose(p->read_fd);
                close(stdout_pipe[1]);
                close(stdin_pipe[0]);
                free(p);
                return 0;
        }

        if (!p->child_pid) {
                /* this is the child process */
                close(stdout_pipe[0]);
                close(stdin_pipe[1]);
                if (stdin_pipe[0] != 0) {
                        dup2(stdin_pipe[0], 0);
                        close(stdin_pipe[0]);
                }
                if (stdout_pipe[1] != 1) {
                        dup2(stdout_pipe[1], 1);
                        close(stdout_pipe[1]);
                }
                if(execve(path, argv, envp)==-1)
                {
                      RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to execve\n",__FUNCTION__);
                      fprintf(stderr, "%s:failed to execve\n", __FUNCTION__);
                      exit(127);
                }
        }

        close(stdout_pipe[1]);
        close(stdin_pipe[0]);
        return p;
}
int spc_pclose(SPC_PIPE *p) {
        int   status;
        pid_t pid;

        if (p->child_pid != -1) {
                do {
                        pid = waitpid(p->child_pid, &status, 0);
                } while (pid == -1 && errno == EINTR);
        }
        //if (p->read_fd) fclose(p->read_fd);
        //if (p->write_fd) fclose(p->write_fd);
        free(p);
        if (pid != -1 && WIFEXITED(status)) return WEXITSTATUS(status);
        else return (pid == -1 ? -1 : 0);
}

int buffer_read(FILE * fptr, char** data){
    int i=0;
    int n_bytes=0;
    int count=0;
    char *output=(char *)calloc(BUF_SIZE, sizeof(char));
    if(output == NULL){
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to allocate memory\n",__FUNCTION__);
        fprintf(stderr, "%s:failed to allocate memory\n", __FUNCTION__);
        return -1;
    }
    while ((count=fread( output+i*BUF_SIZE, 1,BUF_SIZE, fptr)) != 0)
    {
        n_bytes += count;
        if(count != 1024)
            break;
        output = (char*)realloc(output,((++i)*BUF_SIZE+BUF_SIZE)*sizeof(char));
        if(output == NULL){
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to allocate memory\n",__FUNCTION__);
        fprintf(stderr, "%s:failed to allocate memory\n", __FUNCTION__);
            free(output);
            return -1;
        }
    }
    output[n_bytes]='\0';
    *data=output;
    return 0;
}
/* To parse single command to create arguments array which will be passed to execve */
char** cmd_parser(const char* cmd)
{
    int i=0;
    char temp_arg[MAX_LEN+1];
    int n_temp=0;
    if(cmd == NULL)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:invalid command\n",__FUNCTION__);
        fprintf(stderr, "%s:invalid command\n", __FUNCTION__);
        return NULL;
    }
    char **cmd_args= (char **)calloc(MAX_PARAM,sizeof(char *));
    if(cmd_args == NULL)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to allocate memory\n",__FUNCTION__);
        fprintf(stderr, "%s:failed to allocate memory\n", __FUNCTION__);
        return NULL;
    }
    while(cmd[i] != '\0' && n_temp < MAX_PARAM-1)
    {
        int k =0;
        if(cmd[i] == '\'')
        {
            i++;
            while((cmd[i] != '\'') && (cmd[i] != '\0') && (k < MAX_LEN))
            {
                temp_arg[k++]=cmd[i++];
            }
            if(k >= MAX_LEN)
            {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command argument too long\n",__FUNCTION__);
        fprintf(stderr, "%s:command argument too long\n", __FUNCTION__);
                free_arrmem2(cmd_args);
                return NULL;
            }
            if(cmd[i] == '\0')
            {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:invalid command missing ' \n",__FUNCTION__);
        fprintf(stderr, "%s:invalid command missing ' \n", __FUNCTION__);
                free_arrmem2(cmd_args);
                return NULL;
            }
            i++;

        }
        else if(cmd[i] == '\"')
        {
            i++;
            while((cmd[i] != '\"') && (cmd[i] != '\0') && (k < MAX_LEN))
            {
                temp_arg[k++]=cmd[i++];
            }
            if(k >= MAX_LEN)
            {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command argument too long\n",__FUNCTION__);
        fprintf(stderr, "%s:command argument too long\n", __FUNCTION__);
                free_arrmem2(cmd_args);
                return NULL;
            }
            if(cmd[i] == '\0')
            {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:invalid command missing '\"' \n",__FUNCTION__);
        fprintf(stderr, "%s:invalid command missing '\"' \n", __FUNCTION__);
                free_arrmem2(cmd_args);
                return NULL;
            }
            i++;

        }
        else if(cmd[i] != ' ' && cmd[i] != '\t')
        {
            while((cmd[i] != ' ') && (cmd[i] != '\t') && (cmd[i] != '\0') && (k < MAX_LEN))
                temp_arg[k++]=cmd[i++];
            if(k >= MAX_LEN)
            {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command argument too long\n",__FUNCTION__);
        fprintf(stderr, "%s:command argument too long\n", __FUNCTION__);
                free_arrmem2(cmd_args);
                return NULL;
            }

        }
        else
        {
            while(cmd[i] == ' ' || cmd[i] == '\t')
                i++;
        }
        if(k != 0)
        {
            temp_arg[k] = '\0';
            cmd_args[n_temp] = malloc(strnlen(temp_arg, MAX_LEN)+1);
            if(cmd_args[n_temp] == NULL)
               {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to allocate memory\n",__FUNCTION__);
        fprintf(stderr, "%s:failed to allocate memory\n", __FUNCTION__);
                   free_arrmem2(cmd_args);
                   return NULL;
               }
             strncpy(cmd_args[n_temp],temp_arg, strnlen(temp_arg, MAX_LEN)+1);
             n_temp++;
        }
    }
    if(n_temp >= MAX_PARAM-1)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:too many arguments\n",__FUNCTION__);
        fprintf(stderr, "%s:too many arguments\n", __FUNCTION__);        
        free_arrmem2(cmd_args);
        return NULL;
    }
    return cmd_args;
}