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

#ifndef SYSCALL_H
#define SYSCALL_H
/**********************************************************************
    prototype:
        int secure_system_call_p( const char *cmd, char *argp[]);

    Description:

        Implementation of secure system call which takes parameters as
        array.

    Arguments:    const char *                 cmd
                  command to be executed.

                  char *                       argp[]
                  list of parameters to be passed to command
                  argp[0] : must be the command to be executed (cmd)
                  argp[n] : last parameter must be NULL

    Return:       The status of the operation. -1:Failure, 0:Success
**********************************************************************/

int secure_system_call_p( const char *cmd, char *argp[]);

/**********************************************************************
    prototype:
        int secure_system_call_vp( const char *cmd, ...);
    Description:
        Implementation of secure system call which takes variable
        parameters.
    Arguments:    const char *                 cmd
                  command to be executed.
                  ...
                  variable number of arguments (char *)
                  Last argument must be NULL
    Return:       The status of the operation. -1:Failure, 0:Success
**********************************************************************/



int secure_system_call_vp( const char *cmd, ...);

/**********************************************************************
    prototype:
        int v_secure_system( const char* fmt , ...);
    Description:
        Implementation of  v_secure_system which takes variable
        parameters.
    Arguments:    const char *                 fmt
                  command to be executed.
                  ...
                  variable number of arguments (char *)
    Return:       The status of the operation. -1:Failure, 0:Success
**********************************************************************/

int v_secure_system(const char* fmt, ...);

/**********************************************************************
    prototype:
        char* path_find( const char *arg);
    Description:
        Implementation of path_find which takes shell command name as
        parameter.
    Arguments:    const char *              arg
                  
    Return:       command with prepended path 
**********************************************************************/

//char* path_find(const char * arg);

/**********************************************************************
    prototype:
       char* secure_popen_call_p( const char *cmd, char *argp[]);

    Description:

        Implementation of secure popen call which takes parameters as
        array.

    Arguments:    const char *                 cmd
                  command to be executed.

                  char *                       argp[]
                  list of parameters to be passed to command
                  argp[0] : must be the command to be executed (cmd)
                  argp[n] : last parameter must be NULL

    Return:       pointer to output buffer
                  Note: Caller must free this buffer after use
**********************************************************************/




//Implementation of secure popen call which takes parameters as array
//char* secure_popen_call_p( const char *cmd, char *argp[]);

/**********************************************************************
    prototype:
        char* secure_popen_call_vp( const char *cmd, ...);

    Description:

        Implementation of secure popen call which takes variable
        parameters.

    Arguments:    const char *                 cmd
                  command to be executed.

                  ...
                  variable number of arguments (char *)
                  Last argument must be NULL

    Return:       pointer to output buffer
                  Note: Caller must free this buffer after use
**********************************************************************/



//char* secure_popen_call_vp( const char *cmd, ...);




#endif

