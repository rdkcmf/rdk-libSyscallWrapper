/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
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
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WITH_RDKLOGGER
#  include "rdk_debug.h"
//#  define VERBOSE_DEBUG
#  define LOG_LIB "LOG.RDK.LIBSYSCALLWRAPPER"
#else
#  define RDK_LOG(a1, a2, args...) fprintf(stderr, args)
#  define RDK_LOG_INFO 0
#  define RDK_LOG_ERROR 0
#  define LOG_LIB 0
#endif

#define MAX_ARG_LEN 512
#define MAX_NUM_ARGS 512
#define MAX_NUM_CMDS 32
#define MAX_REDIRECTS 8

#define DOUBLE(x) ((x<<8)|x)
#define FAIL(msg...) ({ \
		RDK_LOG(RDK_LOG_ERROR,LOG_LIB, msg); \
		fprintf(stderr, msg); \
		fflush(stderr); \
		goto fail; \
	})
//#define close(fd) ({ (fd < 0) ? -1 : close(fd); })

static FILE *v_secure_popen_internal(const char *direction, const char *format, va_list *ap);

typedef struct {
	char **argv;
	enum {
		UNDEFINED  = 0,
		SEMICOLON  = ';',
		BACKGROUND = '&',
		PIPE = '|',
		AND  = DOUBLE('&'),
		OR   = DOUBLE('|'),
	} token;
	struct {
		int from;
		int to;
	} fds[2 + MAX_REDIRECTS];
	int pipefd;
} task;

static task* new_task() {
	task *new_task = (task *)malloc(sizeof(task));
	if (!new_task) {
		perror("malloc");
		return NULL;
	}

	new_task->argv = (char **)calloc(MAX_NUM_ARGS + 1, sizeof(char *));
	if (!new_task->argv) {
		free(new_task);
		perror("malloc");
		return NULL;
	}

	new_task->token = UNDEFINED;

	memset(new_task->fds, -1, sizeof(new_task->fds));
	new_task->pipefd = -1; // pipe output (stdin of next)

	return new_task;
}

static void free_task(task *task) {
	for (char **argv = task->argv; *argv; argv++) {
		free(*argv);
	}
	free(task->argv);
	free(task);
}

static void free_task_list(task **task_list) {
	for (task **task = task_list; *task; task++) {
		free_task(*task);
	}
	free(task_list);
}

// custom vsnprintf implementation to make sure that ap gets incremented as args are processed
static int _vsnprintf(char *str, size_t size, const char *format, va_list *ap) {
	va_list ap_copy;
	va_copy(ap_copy, *ap);
	int ret = vsnprintf(str, size, format, ap_copy);

	for (const char *ptr = format; *ptr; ptr++) {
		if (ptr[0] == '%') {
			if (ptr[1] == '%') {
				ptr++;
				continue;
			}
			va_arg(*ap, void *);
		}
	}

	return ret;
}

static task **command_parser(const char *format, va_list *ap) {
	int n_tasks = 0;
	task **task_list = (task **)calloc(MAX_NUM_CMDS + 1, sizeof(task *));
	task *current_task = new_task();
	if (!task_list || !current_task) {
		perror("malloc");
		goto fail;
	}

	int n_args = 0;
	int n_redirects = 2; // first two reserved for pipes
	char temp[MAX_ARG_LEN + 1];

	int i = 0; // input position
	int o = 0; // output position (per arg)

	int redirect_token = 0;
	enum {
		UNDEFINED = -1,
		AMP   = -2, // "&>/dev/null"
		// else "n>/dev/null" where n is redirect_fd
	} redirect_fd = UNDEFINED;
	enum {
		DEFAULT,
		NEW_ARG, // force new argument even if empty
		INPLACE, // inplace % format expansion
		REDIR,   // filename for redirect
	} arg_processing = DEFAULT;
	int match;

	do {
		if (o > MAX_ARG_LEN) {
			temp[MAX_ARG_LEN] = '\0';
			FAIL("Argument too long: %s\n", temp);
		}

		if (n_args >= MAX_NUM_ARGS) {
			FAIL("Too many arguments\n");
		}

		if (n_redirects > MAX_REDIRECTS) {
			FAIL("Too many redirects\n");
		}

		if (n_tasks >= MAX_NUM_CMDS) {
			FAIL("Too many commands\n");
		}

		if (current_task == NULL) {
			FAIL("Could not allocate memory for task\n");
		}

		match = format[i];
		switch(match) {
			// whitespace
			case  ' ':
			case '\t':
				i++;
				break;

			// eval & quotations
			case '`':  // eval
			case '\'': // single
			case '\"': // double
			{
				int eval_start = o;
				if (match == '`' && o > 0 && arg_processing != INPLACE) {
					arg_processing = INPLACE;
					break;
				}

				i++; // consume start quote

				while (format[i] != '\0' && format[i] != match && o <= MAX_ARG_LEN) {
					temp[o++] = format[i++];
				}

				if (format[i] == '\0') {
					FAIL("EOF while looking for matching '%c'\n", match);
				}

				i++; // consume end quote

				if (o > MAX_ARG_LEN || match != '`') {
					arg_processing = NEW_ARG;
					continue;
				}

				// eval
				temp[o] = '\0';
				o = eval_start;

				if (!n_args) {
					FAIL("Eval can't be first argument\n");
				}

				FILE *fp = v_secure_popen_internal("r", &temp[o], ap);
				while ((match = fgetc(fp)) != EOF) {
					if (o > MAX_ARG_LEN) {
						temp[MAX_ARG_LEN] = '\0';
						FAIL("Argument too long: %s\n", temp);
					}

					if (n_args >= MAX_NUM_ARGS) {
						FAIL("Too many arguments\n");
					}

					switch(match) {
						case ' ':
						case '\t':
						case '\r':
						case '\n':
							match = fgetc(fp);
							if (o > 0 && match != EOF) {
								temp[o] = '\0';

								char arg[MAX_ARG_LEN + 1];
								_vsnprintf(arg, sizeof(arg), temp, ap);
								arg[MAX_ARG_LEN] = '\0';

								current_task->argv[n_args++] = strdup(arg);
								o = 0;
							}
							ungetc(match, fp);
							break;

						case '%': temp[o++] = '%'; /* Fall */
						default:  temp[o++] = match;
							continue;
					}
				}
				fclose(fp);

				arg_processing = DEFAULT;
				continue;
			}
			// end of command sequences
			case '&': // also &&
			case '|': // also ||
				if (current_task->token != 0) {
					FAIL("unexpected token\n");
				}

				// command &>/dev/null
				if (format[i] == '&' && format[i + 1] == '>') {
					i++;
					redirect_fd = AMP; //&> redirect
					continue;
				}

				if (format[i + 1] == match) {
					current_task->token = DOUBLE(match);
					i += 2;
				} else {
					current_task->token = match;
					i++;
				}
				break;
			case ';':
				current_task->token = match;
				i++;
				break;

			case '\0':
				current_task->token = ';';
				break;

			// file redirects
			case '<':
			case '>': // also >>
				if (redirect_token) {
					FAIL("unexpected redirect\n");
				}

				// parse and consume fd (still sitting in temp due to lack of whitespace before token)
				if (o > 0) {
					temp[o] = '\0';

					char *end = NULL;
					redirect_fd = strtol(temp, &end, 10);
					if (end != &temp[o]) {
						redirect_fd = UNDEFINED;
						break;
					}

					// found fd, consume argument (restart the output buffer)
					o = 0;
				} else if (redirect_fd == UNDEFINED) {
					// assume fd based on direction
					redirect_fd = (match == '<') ? 0 : 1;
				}

				// consume redirect token
				if (format[i + 1] == match) {
					redirect_token = DOUBLE(match);
					i += 2;
				} else {
					redirect_token = match;
					i++;
				}

				// handle "2>&1" redirects
				if (format[i] == '&') {
					i++; // consume &

					char *end = NULL;
					int fd = strtol(&format[i], &end, 10);
					if (end == &format[i]) {
						FAIL("redirect error\n");
					}

					if (redirect_fd == AMP) {
						current_task->fds[n_redirects].from = 1;
						current_task->fds[n_redirects].to = fd;
						n_redirects++;

						current_task->fds[n_redirects].from = 2;
						current_task->fds[n_redirects].to = fd;
						n_redirects++;

					} else {
						current_task->fds[n_redirects].from = redirect_fd;
						current_task->fds[n_redirects].to = fd;
						n_redirects++;
					}

					i = end - format; // consume fd
					redirect_token = 0;
					redirect_fd = UNDEFINED;
					break;
				}

				// filename redirect; we'll pick up the filename after the switch loop
				arg_processing = REDIR;
				break;

			// normal arguments
			default:
				temp[o++] = format[i++];
				continue;
		}
		// switch statement blocks until a full argument is parsed

		if (o > 0 || arg_processing == NEW_ARG) {
			temp[o] = '\0';

			char arg[MAX_ARG_LEN + 1];
			o = _vsnprintf(arg, sizeof(arg), temp, ap);
			arg[MAX_ARG_LEN] = '\0';

			if (o > MAX_ARG_LEN) {
				FAIL("Argument too long: %s\n", arg);
			}

			switch (arg_processing) {
				case NEW_ARG:
				default:
					current_task->argv[n_args++] = strdup(arg);
					break;

				case INPLACE:
					o = 0;
					for (char *c = arg; *c; c++) {
						switch (*c) {
							case '%': temp[o++] = '%'; /* Fall */
							default:  temp[o++] = *c;
						}
					}
					continue; // stay INPLACE

				case REDIR:
				{
					if (strcmp(temp, arg) != 0) {
						FAIL("redirection to variable is insecure\n");
					}

					int fd = -1;
					switch (redirect_token) {
						case '<':         fd = open(temp, O_RDONLY); break;
						case '>':         fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC,  0644); break;
						case DOUBLE('>'): fd = open(temp, O_WRONLY | O_CREAT | O_APPEND, 0644); break;

						default: FAIL("unsupported redirect\n");
					}

					if (fd < 0) {
						perror(temp);
					} else if (redirect_fd == AMP) { // &> redirect

						current_task->fds[n_redirects].from = 1;
						current_task->fds[n_redirects].to = fd;
						n_redirects++;

						current_task->fds[n_redirects].from = 2;
						current_task->fds[n_redirects].to = dup(fd);
						n_redirects++;
					} else {
						current_task->fds[n_redirects].from = redirect_fd;
						current_task->fds[n_redirects].to = fd;
						n_redirects++;
					}

					redirect_token = 0;
					redirect_fd = UNDEFINED;

					break;
				}
			}

			o = 0;
			arg_processing = DEFAULT;
		}

		// token means we've reached the end of a command
		if (n_args && current_task->token) {
			task_list[n_tasks++] = current_task;
			current_task = new_task();
			if (!current_task) {
				FAIL("malloc");
			}
			n_args = 0;
			n_redirects = 2;
		}
	} while (match);

	free_task(current_task);
	return task_list;

fail:
	if (current_task) free_task(current_task);
	if (task_list) free_task_list(task_list);
	return NULL;
}

static int execute_task(const task *current_task) {
	char **argv = current_task->argv;
	int ret = -1;

#ifdef VERBOSE_DEBUG
	for (int n=0; current_task->argv[n]; n++) {
		RDK_LOG(RDK_LOG_INFO, LOG_LIB, "arg%d: \"%s\"\n", n, current_task->argv[n]);
	}
#endif

	fflush(stdout);
	fflush(stderr);

	pid_t child_pid = fork();
	if (child_pid == -1) {
		perror("fork");
	} else if (!child_pid) {
		if (current_task->token == BACKGROUND || current_task->token == PIPE) {
			// execve will be grandchild with the immediate parent exiting to disown it
			if (fork() > 0) {
				_exit(0);
			}
		}

		for (int n = 0; n < MAX_REDIRECTS; n++) {
			if (current_task->fds[n].from == -1) {
				continue;
			}
			close(current_task->fds[n].from);
			dup2(current_task->fds[n].to, current_task->fds[n].from);
			if (current_task->fds[n].to > 2) {
				close(current_task->fds[n].to);
			}
		}

		close(current_task->pipefd);

		if (execvp(argv[0], argv) == -1) {
			perror(argv[0]);
		}

		_exit(-1);
	} else {
		int wstatus;
		if (waitpid(child_pid, &wstatus, 0) == -1) {
			fprintf(stderr, "child exited unexpectedly\n");
		}

		if (WIFEXITED(wstatus)) {
			ret = WEXITSTATUS(wstatus);
		}

#ifdef VERBOSE_DEBUG
		RDK_LOG(RDK_LOG_INFO, LOG_LIB, "ret: %d\n", ret);
#endif

		for (int n = 0; n < MAX_REDIRECTS; n++) {
			if (current_task->fds[n].to > 2) {
				close(current_task->fds[n].to);
			}
		}
	}

	return ret;
}

static int v_secure_system_internal(const char *format, va_list *ap) {
#ifdef VERBOSE_DEBUG
	va_list ap_log;
	char cmd_log[1024];

	va_copy(ap_log, *ap);
	vsnprintf(cmd_log, sizeof(cmd_log), format, ap_log);
	cmd_log[sizeof(cmd_log)-1] = '\0';
	RDK_LOG(RDK_LOG_INFO, LOG_LIB, "wrapper template: %s\n", format);
	RDK_LOG(RDK_LOG_INFO, LOG_LIB, "wrapper command: %s\n", cmd_log);
#endif

	int ret = -1;

	int skip = 0;    // short circuit evaluation when using AND, OR
	int pipefd = -1; // output of previous pipe (mapped to stdin)

	task **task_list = command_parser(format, ap);

	for (int n_tasks = 0; n_tasks < MAX_NUM_CMDS && task_list && task_list[n_tasks]; n_tasks++) {
		task *current_task = task_list[n_tasks];
		if (!skip) {

			if (pipefd != -1) {
				current_task->fds[0].from = 0;
				current_task->fds[0].to = pipefd;
				pipefd = -1;
			}

			if (current_task->token == PIPE) {
				int pipes[2];

				if (pipe(pipes) == -1) {
					perror("pipe");
					goto fail;
				}

				current_task->fds[1].from = 1;
				current_task->fds[1].to = pipes[1];

				current_task->pipefd = pipes[0];
				pipefd = current_task->pipefd;
			}

			ret = execute_task(current_task);

		} else if (current_task->token == PIPE) {
			// skipped_command | another_skipped_command
			skip++;
		}

		if (skip > 0) {
			// skipped_command ; command
			skip--;
		}

		if (ret == 0 && current_task->token == OR) {
			// true_command || skipped_command
			skip++;
		}

		if (ret != 0 && current_task->token == AND) {
			// false_command && skipped_command
			skip++;
		}
	}

fail:
	if (task_list) {
		free_task_list(task_list);
	}
	return ret;
}

int v_secure_system(const char *format, ...) {
	int ret;
	va_list ap;

	va_start(ap, format);
	ret = v_secure_system_internal(format, &ap);
	va_end(ap);

	return ret;
}

/*
 * popen() wrapper
 */

typedef struct {
	int fd;
	int pid;
} pstatus;

static ssize_t secure_popen_read(void *cookie, char *buf, size_t size) {
	return read(((pstatus *)cookie)->fd, buf, size);
}

static ssize_t secure_popen_write(void *cookie, const char *buf, size_t size) {
	return write(((pstatus *)cookie)->fd, buf, size);
}

static int secure_popen_close(void *cookie) {
	pstatus *c = (pstatus *)cookie;
	int ret = -1;

	close(c->fd);

	int wstatus;
	if (waitpid(c->pid, &wstatus, 0) == -1) {
		fprintf(stderr, "child exited unexpectedly\n");
	}

	if (WIFEXITED(wstatus)) {
		ret = WEXITSTATUS(wstatus);
	}

	free(cookie);

	return ret;
}

static cookie_io_functions_t popen_file = {
	.read  = secure_popen_read,
	.write = secure_popen_write,
	.close = secure_popen_close,
};

static FILE *v_secure_popen_internal(const char *direction, const char *format, va_list *ap) {
	pstatus *cookie = (pstatus *)malloc(sizeof(*cookie));
	pid_t child_pid;
	int pipes[2];
	int dir = (*direction == 'r') ? 1 : 0;

	if (!cookie) {
		perror("malloc");
		return NULL;
	}

	if (pipe(pipes) == -1) {
		perror("pipe");
		goto fail;
	}

	fflush(stdout);
	fflush(stderr);

	child_pid = fork();
	if (child_pid == -1) {
		perror("fork");
		goto fail;

	} else if (child_pid == 0) {
		close(dir);
		close(pipes[1 - dir]);
		dup2(pipes[dir], dir);

		int child_ret = v_secure_system_internal(format, ap);

		_exit(child_ret);
		/* noreturn */
	}

	// this is just to make sure we burn through the va_arg on the parent thread
	char dummy[MAX_ARG_LEN + 1];
	_vsnprintf(dummy, sizeof(dummy), format, ap);

	cookie->pid = child_pid;

	close(pipes[dir]);
	cookie->fd = pipes[1 - dir];
	return fopencookie((void *)cookie, dir ? "r" : "w", popen_file);

fail:
	free(cookie);
	return NULL;
}

FILE *v_secure_popen(const char *direction, const char *format, ...) {
	FILE *ret;
	va_list ap;

	va_start(ap, format);
	ret = v_secure_popen_internal(direction, format, &ap);
	va_end(ap);

	return ret;
}

int v_secure_pclose(FILE *stream) {
	// triggers secure_popen_close();
	return fclose(stream);
}


/*
 * Legacy API compatibility
 */

int contains_secure_separator(char *str) {
	return -1;
}

int secure_system_call_p(const char *cmd, char *argv[]) {
	int ret = -1;

#ifdef VERBOSE_DEBUG
	for (int n=0; argv[n]; n++) {
		RDK_LOG(RDK_LOG_INFO, LOG_LIB, "arg%d: \"%s\"\n", n, argv[n]);
	}
#endif

	pid_t child_pid = fork();
	if (child_pid == -1) {
		return -1;
	} else if (!child_pid) {
		if (execvp(argv[0], argv) == -1) {
			perror(argv[0]);
		}

		_exit(-1);
	} else {
		int wstatus;
		if (waitpid(child_pid, &wstatus, 0) == -1) {
			fprintf(stderr, "child exited unexpectedly\n");
		}

		if (WIFEXITED(wstatus)) {
			ret = WEXITSTATUS(wstatus);
		}

#ifdef VERBOSE_DEBUG
		RDK_LOG(RDK_LOG_INFO, LOG_LIB, "ret: %d\n", ret);
#endif
	}
	return ret;
}

int secure_system_call_vp(const char *cmd, ...) {
	int ret = -1;

	if (cmd == NULL) {
		FAIL("NULL input given\n");
	}

	char *arg[MAX_NUM_ARGS + 1];

	char *temp_arg;
	int n_args = 0;
	va_list ap;

	arg[n_args++] = (char *)cmd;

	va_start(ap, cmd);
	do {
		if (n_args >= MAX_NUM_ARGS) {
			va_end(ap);
			FAIL("Too many arguments\n");
		}

		temp_arg = arg[n_args++] = va_arg(ap, char *);

	} while(temp_arg);

	ret = secure_system_call_p(cmd, arg);
fail:
	return ret;
}
