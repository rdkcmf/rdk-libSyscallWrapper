#include <stdio.h>
#include <stdlib.h>

#ifndef __SECURE_H
#  define __SECURE_H
#  ifdef __cplusplus
extern "C" {
#  endif

__attribute__((nonnull))
__attribute__((format(printf,1,2)))
int v_secure_system(const char *command, ...);

__attribute__((nonnull))
__attribute__((format(printf,2,3)))
FILE *v_secure_popen(const char *direction, const char *command, ...);

__attribute__((nonnull))
int v_secure_pclose(FILE *);

/* OBSOLETE CONSTANTS */
#define _SPIPE "|"
#define _SOR "||"
#define _SAND "&&"
#define _SBG "&"
#define _STHEN ";"

/* The following is just some gcc magic to make sure
 * 1) the format string isn't a variable
 * 2) the number of arguments matches the format
 * 3) popen's direction arg is "r" or "w"
 */
#define v_secure_system(fmt, args...) \
	({ \
		int ret; \
		_Pragma("GCC diagnostic push") \
		_Pragma("GCC diagnostic error \"-Wformat\"") \
		_Pragma("GCC diagnostic error \"-Wformat-security\"") \
		if (!__builtin_constant_p(fmt)) { \
		extern void format_error() __attribute__((error("command argument cannot be a variable\nreplace \"sprintf(buffer, command, args); v_secure_system(buffer);\" with \"v_secure_system(command, args);\""))); \
			format_error(); \
		} \
		ret = v_secure_system(fmt, ##args); \
		_Pragma("GCC diagnostic pop") \
		ret; \
	})

#define v_secure_popen(direction, fmt, args...) \
	({ \
		FILE *ret; \
		_Pragma("GCC diagnostic push") \
		_Pragma("GCC diagnostic error \"-Wformat\"") \
		_Pragma("GCC diagnostic error \"-Wformat-security\"") \
		if ( \
			__builtin_constant_p(*direction) && \
			((direction[0] != 'r' && direction[0] != 'w') || direction[1] != '\0') \
		) { \
			extern void popen_check() __attribute__((error("v_secure_popen(direction, command, ...) direction must be \"r\" or \"w\""))); \
			popen_check(); \
		} \
		if (!__builtin_constant_p(fmt)) { \
			extern void format_error() __attribute__((error("command argument cannot be a variable"))); \
			format_error(); \
		} \
		ret = v_secure_popen(direction, fmt, ##args); \
		_Pragma("GCC diagnostic pop") \
		ret; \
	})

extern int system(const char *command) __attribute__((warning("please replace system() with v_secure_system()")));

extern int contains_secure_separator(char *str) __attribute__((warning("contains_secure_separator is obsolete")));
extern int secure_system_call_p(const char *cmd, char *argv[]);
extern int secure_system_call_vp(const char *cmd, ...);

#  ifdef __cplusplus
}
#  endif
#endif
