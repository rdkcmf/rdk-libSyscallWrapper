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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "secure_wrapper.h"

#ifdef CCSP_TRACE
#include "ccsp_trace.h"
#endif //CCSP_TRACE


#define MAX_PARAM  1024
#define CMD_PARAM 512
#define NUM_PARAM 30
#define STRINGCMP(sent,word) (strcmp(sent, word) == 0)

char smd[CMD_PARAM];

int secure_system_call_p( const char *cmd, char *argp[])
{
    pid_t pid;
    int cmd_check;
    int count=0;
    extern char** environ;  /* Take the default env, defined in unistd.h */

    fprintf(stderr, "%s,Command %s\n", __FUNCTION__, cmd);
    fprintf(stdout, "%s,Command %s\n", __FUNCTION__, cmd);
#ifdef CCSP_TRACE
    CcspTraceWarning(("%s,Command %s\n", __FUNCTION__, cmd));
#endif//CCSP_TRACE
        pid_t pid;
        int cmd_check;
        int count=0;
        extern char** environ;  /* Take the default env, defined in unistd.h */

        if ((cmd == NULL)||(*argp == NULL))
        {
                fprintf(stderr, "%s:bad input!!!\n", __FUNCTION__);
#ifdef CCSP_TRACE
        CcspTraceWarning(("%s:bad input!!!\n", __FUNCTION__));
#endif//CCSP_TRACE
        return -1;
    }

    cmd_check=(STRINGCMP(cmd,"/bin/sh") || STRINGCMP(cmd,"sh"));
    while(argp[count]) {
        /* ... Sanitize arguments ...if command is /bin/sh or sh */
        if (cmd_check && (argp[count] && (STRINGCMP(argp[count], "-c")))) {
            fprintf(stderr, "%s:Bad input, command rejected\n", __FUNCTION__);
#ifdef CCSP_TRACE
            CcspTraceWarning(("%s:Bad input, command rejected\n", __FUNCTION__));
#endif//CCSP_TRACE
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
#ifdef CCSP_TRACE
        CcspTraceWarning(("%s,executing command %s\n", __FUNCTION__, cmd));
#endif//CCSP_TRACE
                if (execve(cmd, argp, environ) == -1){ /* Handle error */
                        fprintf(stderr, "%s:Failed to execve\n", __FUNCTION__);
#ifdef CCSP_TRACE
            CcspTraceWarning(("%s:Failed to execve\n", __FUNCTION__));
#endif//CCSP_TRACE
            return -1;
        }
    }

    return 0;
}

int secure_system_call_vp( const char *cmd, ...)
{
    int status;
    char * arg[MAX_PARAM+1];
    char *temp_arg=NULL;
    int num_param=0;
    va_list arguments;

    if (cmd == NULL) {
        fprintf(stderr, "%s:bad input!!!\n", __FUNCTION__);
#ifdef CCSP_TRACE
        CcspTraceWarning(("%s:bad input!!!\n", __FUNCTION__));
#endif//CCSP_TRACE
        return -1;
    }

    arg[0]=(char *)cmd; //arg[0] contains name execuatble filename

    /*count number of incoming parameters*/
    va_start(arguments,cmd);
    do {
        if (num_param >= MAX_PARAM) {
            fprintf(stderr, "%s:Parameter list too large\n", __FUNCTION__);
#ifdef CCSP_TRACE
            CcspTraceWarning(("%s:Parameter list too large\n", __FUNCTION__));
#endif//CCSP_TRACE
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


char* path_find(const char * arg)
{
    char cpath[CMD_PARAM] = {'\0'};
    char* pathcpy = cpath;
    char* path = NULL;

    /* Ignore if file is absolute or relative.
     */
    if ((arg[0] == '/') || (arg[0] == '.')) {
        struct stat fd;
        snprintf(smd, sizeof(smd), "%s",arg);
        if (stat(smd, &fd) == 0) {
            return smd;
        } else {
            return NULL;
        }
    }

    /* Copy path environment string and null terminate. */
    strncpy(cpath, getenv("PATH"), CMD_PARAM-1)[CMD_PARAM-1] = '\0';

    /* Recursively check each path from within PATH
     * environment.
     * If file exists within that path, return
     * the absolute path to the file.
     */
    while ((path = strtok_r(pathcpy, ":", &pathcpy))) {
        if (path != NULL) {
            struct stat fd;
            snprintf(smd, sizeof(smd), "%s/%s", path, arg);
            if (stat(smd, &fd) == 0) {
                /* File exists in path, return absolute. */
                return smd;
            }
        }
    }

    /* No file found */
    #ifdef CCSP_TRACE
    CcspTraceWarning(("%s:PATH NOT FOUND for command:%s\n", __FUNCTION__, arg));
    #else
    fprintf(stderr, "%s:PATH NOT FOUND for command:%s\n", __FUNCTION__, arg);
    #endif//CCSP_TRACE
    return NULL;
}

int v_secure_system(const char* fmt, ...)
{
    char cmd[CMD_PARAM];
    va_list ap;
    int n;
    char* args[MAX_PARAM];
    int num_param = 0;
    char* temp;
    char* line;
    int status;

    va_start(ap, fmt);
    n = vsnprintf(cmd, sizeof(cmd), fmt, ap);
    if (n < 0 || n >= sizeof(cmd)) {
         fprintf(stderr, "%s:command is too large \n", __FUNCTION__);
#ifdef CCSP_TRACE
         CcspTraceWarning(("%s:command is too large \n", __FUNCTION__));
#endif//CCSP_TRACE
         va_end(ap);
         return -1;
    }
    va_end(ap);

    line = (char *)cmd;

    while ((temp = strtok_r(line, " ", &line))) {
        if(num_param <= MAX_PARAM-2) {
            args[num_param++] = temp;
        } else {
            fprintf(stderr, "%s:Parameter list too large \n", __FUNCTION__);
#ifdef CCSP_TRACE
            CcspTraceWarning(("%s:Parameter list too large \n", __FUNCTION__));
#endif//CCSP_TRACE
            return -1;
        }
    }

    args[num_param] = NULL;
    args[0] = path_find(args[0]);
    status = secure_system_call_p(args[0], args);
    return status;
}

/* #define TEST_MODE */

#ifdef TEST_MODE
int main() {
    /* Create a file secure_test.sh somewhere in your path */
    if (v_secure_system("secure_test.sh t1 t2") == 0) {
        printf("OK");
    }
}
#endif
