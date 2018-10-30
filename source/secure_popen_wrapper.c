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

#define MAX_LEN 128 
#define MAX_PARAM 31 //including NULL terminator for list
#define CMD_SIZE 1024
#define PATH_SIZE 1024
#define BUF_SIZE 1024
#define STRINGSTR(sent,word) (strstr(sent, word) != NULL)
#define STRINGNCMP(sent,word,size) (strncmp(sent, word, size) == 0)
#define LOG_LIB "LOG.RDK.LIBSYSCALLWRAPPER"

typedef struct {
        FILE  *read_fd;
        FILE  *write_fd;
        pid_t child_pid;
} SPC_PIPE;

FILE* v_secure_popen(const char* fmt, ...)
{
    char cmd[CMD_SIZE]={'\0'};
    char* line=NULL;
    char* temp=NULL;
    va_list  ap;
    int n=0;
    int max_cmd=0;
    SPC_PIPE* cmd_pipe=NULL;
    FILE* fptr=NULL;
    va_start(ap, fmt);
    char *data = NULL;
    int status = 0;
    int count=0;
    int cmd_check=0;
    int flag=1;
    extern char** environ;  /* Take the default env, defined in unistd.h */
    /* creating single  command buffer with all inputs arguments,
       replacing "%" with actual values */
    n = vsnprintf(cmd, sizeof(cmd), fmt, ap);
    if (n < 0 || n >= sizeof(cmd))
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command invalid\n", __FUNCTION__);
        //fprintf(stderr,"%s:command invalid\n",__FUNCTION__);
        va_end(ap);
        return NULL;
    }
    va_end(ap);
    line=(char *)cmd;
    temp=strtok_r(line,"|", &line);
    while((max_cmd <= MAX_PARAM) && (temp != NULL))
    {
        char** cmd_args=NULL;
        cmd_args=cmd_parser(temp);
        if(cmd_args == NULL)
        {
            RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:parsing failed for command\n", __FUNCTION__);
            fprintf(stderr,"%s:parsing failed for command\n",__FUNCTION__);
            if(data != NULL)
            {
                free(data);
            }
            return NULL;
        }
        if(cmd_args[0] != NULL)
        {
            char* temp_path=NULL;
            temp_path=path_finder(cmd_args[0]);
            if(temp_path == NULL)
            {
                free_arrmem2(cmd_args);
                if(data != NULL)
                   free(data);
                return NULL;
            }
            free(cmd_args[0]);//replace cmd_args with temp_path
            cmd_args[0]=temp_path;
        }
        cmd_check=(STRINGSTR(cmd_args[0],"/bin/sh") || STRINGNCMP(cmd_args[0],"sh", strnlen(cmd_args[0], MAX_LEN)) 
                   || STRINGSTR(cmd_args[0],"/bin/bash") || STRINGNCMP(cmd_args[0],"bash", strnlen(cmd_args[0], MAX_LEN)));
        while(cmd_args[count]) {
            /* ... Sanitize arguments ...if command is /bin/sh or sh */
            if (cmd_check && (cmd_args[count] && cmd_args[count][0]=='-' && (STRINGSTR(cmd_args[count], "c")))) {
                RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:Bad input, command rejected\n", __FUNCTION__);
                fprintf(stderr,"%s:Bad input, command rejected\n",__FUNCTION__);
                free_arrmem2(cmd_args);
                if(data != NULL)
                {
                    free(data);
                }
                return NULL;
            }
            count++;
        }
        
           if(flag==1)
           {
            RDK_LOG(RDK_LOG_INFO,LOG_LIB,"%s calling : %s \n", __FUNCTION__,cmd_args[0]);
            //fprintf(stdout,"%s calling :%s\n",__FUNCTION__,cmd_args[0]);
            flag = 0;
           }
        cmd_pipe=spc_popen(cmd_args[0], cmd_args, environ);
        if(cmd_pipe->read_fd) fptr = cmd_pipe->read_fd;
        if(max_cmd != 0)// skip first command iteration
        {
            if(data != NULL)
            {
                fprintf(cmd_pipe->write_fd, "%s",data);
                free(data);
            }
        }
        if(cmd_pipe->write_fd)fclose(cmd_pipe->write_fd);
        temp=strtok_r(NULL, "|", &line);
        if(temp == NULL)// if this is the last iteration then return the file pointer of output data to calling function
        {
            free_arrmem2(cmd_args);
            spc_pclose(cmd_pipe);
            break;
        }
        status = buffer_read(cmd_pipe->read_fd, &data);
        if(status == -1)
        {
            RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to allocate memory\n", __FUNCTION__);
            fprintf(stderr,"%s:failed to allocate memory\n",__FUNCTION__);
            free_arrmem2(cmd_args);
            spc_pclose(cmd_pipe);
            return NULL;
        }
        free_arrmem2(cmd_args);
        max_cmd++;
        spc_pclose(cmd_pipe);
        if(fptr != NULL) fclose(fptr);
    }
    if(max_cmd > MAX_PARAM)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:too many commands \n", __FUNCTION__);
        fprintf(stderr,"%s:too many commands \n",__FUNCTION__);
        free(data);
        return NULL;
    }
    return fptr;

}

int v_secure_pclose(FILE* fptr)
{
    if(fptr == NULL) return -1;
    fclose(fptr);
    return 0; 
}
