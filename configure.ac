##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AC_PREREQ([2.65])
AC_INIT([libsyswrapper], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

TRACE_CFLAGS=" "
TRACE_LIBS==" "

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

AC_ARG_ENABLE([ccsptrace],
              AS_HELP_STRING([--enable-ccsptrace],[enable ccsp based tracing (default is no)]),
              [
                case "${enableval}" in
                 yes) TRACE_CFLAGS="-DCCSP_TRACE -I=${includedir}/ccsp"
                      TRACE_LIBS="-lccsp_common";;
                 no) echo[videouploader library & binary support is disabled];;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dtcpdec]) ;;
                esac
              ],
              [echo "ccsp based tracing is disabled"])

#check for test program

AC_ARG_ENABLE([testapp],
              AS_HELP_STRING([--enable-testapp],[enable testing application of secure wrapper (default is no)]),
              [
                case "${enableval}" in
                 yes) ENABLE_TEST_APP=true;;
                 no) ENABLE_TEST_APP="",	echo[testing app is disabled];;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-testapp]) ;;
                esac
              ],
              [echo "test application is disabled by default"])

AM_CONDITIONAL([ENABLE_TEST_APP], [test x$ENABLE_TEST_APP = xtrue])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(TRACE_CFLAGS)
AC_SUBST(TRACE_LIBS)
AC_CONFIG_FILES(
    source/Makefile
      Makefile
    testapp/Makefile
    )
AC_OUTPUT


