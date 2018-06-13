/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>   
#include <stdarg.h>
#include <sys/stat.h>
#include "rdk_debug.h"

#define CMD_PARAM 512
#define MAX_LEN 256
#define MAX_PARAM 31
#define CMD_SIZE 1024
#define BUF_SIZE 1024
#define STRINGSTR(sent,word) (strstr(sent, word) != NULL)
//#define STRINGCMP(sent,word) (strcmp(sent, word) == 0)
#define STRINGNCMP(sent,word,size) (strncmp(sent, word, size) == 0)
#define LOG_LIB "LOG.RDK.LIBSYSCALLWRAPPER"

const char* pDebugConfig = "/etc/debug.ini";
int b_rdk_logger_enabled = 0;

typedef struct {
        FILE  *read_fd;
        FILE  *write_fd;
        pid_t child_pid;
} SPC_PIPE;

int secure_system_call_p( const char *cmd, char *argp[])
{
    pid_t pid;
    int cmd_check;
    int count=0;
    extern char** environ;  /* Take the default env, defined in unistd.h */

    fprintf(stderr, "%s,Command %s\n", __FUNCTION__, cmd);
    fprintf(stdout, "%s,Command %s\n", __FUNCTION__, cmd);

    if ((cmd == NULL)||(*argp == NULL)) {
        fprintf(stderr, "%s:bad input!!!\n", __FUNCTION__);
        return -1;
    }

    //cmd_check=(STRINGCMP(cmd,"/bin/sh") || STRINGCMP(cmd,"sh"));
    cmd_check =(STRINGSTR(cmd,"/bin/sh") || STRINGNCMP(cmd,"sh", strnlen(cmd, MAX_LEN))
                || STRINGSTR(cmd,"/bin/bash") || STRINGNCMP(cmd,"bash", strnlen(cmd, MAX_LEN)));
    while(argp[count]) {
        /* ... Sanitize arguments ...if command is /bin/sh or sh */
        if (cmd_check && (argp[count] && argp[count][0]=='-' && (STRINGSTR(argp[count], "c")))) {
            RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:Bad input, command rejected\n", __FUNCTION__);
            fprintf(stderr, "%s:Bad input, command rejected\n", __FUNCTION__);
            return -1;
        }
        count++;
    }

    pid = fork();
    if (pid == -1){ /* Handle error */
        printf(" Failed to fork!!!\n");
        return -1;
    } else if (pid != 0) {
        printf(" inside parent process\n");
    } else {
        fprintf(stderr, "%s,executing command %s\n", __FUNCTION__, cmd);
        if (execve(cmd, argp, environ) == -1) { /* Handle error */
            fprintf(stderr, "%s:Failed to execve\n", __FUNCTION__);
            return -1;
        }
    }

    return 0;
}

int secure_system_call_vp( const char *cmd, ...)
{
    int status;
    char * arg[CMD_SIZE+1];
    char *temp_arg=NULL;
    int num_param=0;
    va_list arguments;

    if (cmd == NULL) {
        fprintf(stderr, "%s:bad input!!!\n", __FUNCTION__);
        return -1;
    }

    arg[0]=(char *)cmd; //arg[0] contains name execuatble filename

    /*count number of incoming parameters*/
    va_start(arguments,cmd);
    do {
        if (num_param >= CMD_SIZE) {
            fprintf(stderr, "%s:Parameter list too large\n", __FUNCTION__);
            va_end(arguments);
            return -1;
        } else {
            num_param++;
            temp_arg = arg[num_param] = va_arg(arguments, char*);
        }
    } while(temp_arg);
    va_end(arguments);

    status = secure_system_call_p(cmd,arg);
    return status;
}

SPC_PIPE* v_system(char * cmd)
{
    int count=0;
    int cmd_check=0;
    SPC_PIPE* cmd_pipe=NULL;
    extern char** environ;
    char** cmd_args=NULL;
    cmd_args=cmd_parser(cmd);
    if(cmd_args == NULL)
    {
      RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:parsing failed for command\n", __FUNCTION__);
      fprintf(stderr, "%s:parsing failed for command\n", __FUNCTION__); 
      return NULL;
    }
    if(cmd_args[0] != NULL)
    {
        char* temp_path=NULL;
        temp_path=path_finder(cmd_args[0]);
        if(temp_path == NULL)
        {
            free_arrmem2(cmd_args);
            return NULL;
        }
        free(cmd_args[0]);//replace cmd_args with temp_path
        cmd_args[0]=temp_path;
    }
    cmd_check=(STRINGSTR(cmd_args[0],"/bin/sh") || STRINGNCMP(cmd_args[0],"sh", strnlen(cmd_args[0], MAX_LEN))
               ||STRINGSTR(cmd_args[0],"/bin/bash") || STRINGNCMP(cmd_args[0],"bash", strnlen(cmd_args[0], MAX_LEN)));
    while(cmd_args[count]) {
        /* ... Sanitize arguments ...if command is /bin/sh or sh */
        if (cmd_check && (cmd_args[count] && cmd_args[count][0]=='-' && (STRINGSTR(cmd_args[count], "c")))) {
            RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:Bad input, command rejected\n", __FUNCTION__);
            fprintf(stderr,"%s:Bad input, command rejected\n",__FUNCTION__);
            free_arrmem2(cmd_args);
            return NULL;
        }
        count++;
    }
    cmd_pipe=spc_popen(cmd_args[0], cmd_args, environ);
    return cmd_pipe;   
}

int v_secure_system_nested(char* cmd)
{
    char* temp=NULL;
    int max_cmd=0;
    SPC_PIPE* cmd_pipe=NULL;
    char *data = NULL;
    int status = 0;
    int buff=0;
    /* creating single  command buffer with all inputs arguments,
       replacing "%" with actual values */
    if (cmd ==NULL)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command invalid\n", __FUNCTION__);
        fprintf(stderr, "%s:command invalid\n", __FUNCTION__);
        return -1;
    }
    temp=strtok_r(cmd,"|",&cmd);
    while((max_cmd <= MAX_PARAM) && temp!=NULL)
    { 
        cmd_pipe=v_system(temp);
        if(cmd_pipe==NULL)
        {
            if(data != NULL) free(data);
            return -1;
        }
        if(max_cmd != 0)
        {
            if(data != NULL)
            {
                fprintf(cmd_pipe->write_fd, "%s",data);
                free(data);
            }
        }
        if(cmd_pipe->write_fd)fclose(cmd_pipe->write_fd);
        buff = buffer_read(cmd_pipe->read_fd, &data);
        if(buff == -1)
        {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:failed to allocate memory\n", __FUNCTION__);
        fprintf(stderr, "%s:failed to allocate memory\n", __FUNCTION__);
            if(cmd_pipe->read_fd)fclose(cmd_pipe->read_fd);
            spc_pclose(cmd_pipe);
            return -1;
        }
        max_cmd++;
        if(cmd_pipe->read_fd)fclose(cmd_pipe->read_fd);
        spc_pclose(cmd_pipe);
        temp=strtok_r(cmd,"|",&cmd);
    }
    if(max_cmd > MAX_PARAM)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:too many commands \n", __FUNCTION__);
        fprintf(stderr, "%s:too many commands \n", __FUNCTION__);
        free(data);
        return -1;
    }
    return status;
}


int v_secure_system_conditional(char* cmd)
{
    char* temp=NULL;
    char* data=NULL;
    int status=0;
    SPC_PIPE * cmd_pipe=NULL;
    int max_cmd=0;
    /* creating single  command buffer with all inputs arguments,
       replacing "%" with actual values */
    if (cmd==NULL)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command invalid\n", __FUNCTION__);
        fprintf(stderr, "%s:command invalid\n", __FUNCTION__);
        return -1;
    }
    while((max_cmd <= MAX_PARAM) && (temp=strtok_r(cmd,"&&", &cmd)) && temp!=NULL)
    {
        if(status==0)
        {          
             cmd_pipe=v_system(temp);
             if(cmd_pipe==NULL)
             return -1;
             if(cmd_pipe->write_fd) fclose(cmd_pipe->write_fd);
             if(cmd_pipe->read_fd)  fclose(cmd_pipe->read_fd); 
             status=spc_pclose(cmd_pipe);
        }
        else
             return -1;
        max_cmd++;
    }
    if(max_cmd > MAX_PARAM)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:too many commands \n", __FUNCTION__);
        fprintf(stderr, "%s:too many commands \n", __FUNCTION__);
        return -1;
    }
    return status;
}
int v_secure_system(const char* fmt, ...)
{
    char* cmd  = (char *)calloc(CMD_PARAM,sizeof(char));
    char* line=NULL;
    char* data=NULL;
    va_list  ap;
    int n=0,status=0;
    SPC_PIPE * cmd_pipe=NULL;
    if(b_rdk_logger_enabled == 0){
        rdk_logger_init(pDebugConfig);
        b_rdk_logger_enabled = 1;
    }
     
    va_start(ap, fmt);
    /* creating single  command buffer with all inputs arguments,
       replacing "%" with actual values */
    n = vsnprintf(cmd, CMD_PARAM-1, fmt, ap);
    if (n < 0 || n >= CMD_PARAM-1)
    {
        RDK_LOG(RDK_LOG_ERROR,LOG_LIB,"%s:command invalid\n", __FUNCTION__);
        fprintf(stderr, "%s:command invalid\n", __FUNCTION__);
        va_end(ap);
        free(cmd);
        return -1;

    }
    va_end(ap);
    line=cmd;
    RDK_LOG(RDK_LOG_INFO,LOG_LIB,"%s calling : %s\n", __FUNCTION__,line);
    fprintf(stdout,"%s calling :%s\n",__FUNCTION__,line);
    if(STRINGSTR(line,"|"))
    {
        status = v_secure_system_nested(line);
    }
    else if(STRINGSTR(line,"&&"))
    {
        status = v_secure_system_conditional(line);
    }
    else  //simple command
    {
        cmd_pipe = v_system(line);
        if(cmd_pipe==NULL)
        {
            free(cmd);
            return -1;
        }
        if(cmd_pipe->write_fd) fclose(cmd_pipe->write_fd);
        if(cmd_pipe->read_fd) fclose(cmd_pipe->read_fd);
        status=spc_pclose(cmd_pipe);        
    }
    free(cmd);
    return status;
}
