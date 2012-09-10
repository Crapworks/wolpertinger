dnl Process this file with autoconf to produce a configure script.
dnl Created by Anjuta application wizard.

AC_INIT(wolpertinger, 0.5)

AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

dnl disable compiler optimisation
AC_ISC_POSIX
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_STDC
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/time.h unistd.h pcap.h sqlite3.h openssl/evp.h dnet.h uuid/uuid.h],[],[AC_MSG_ERROR([required header files missing])])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select socket strdup strtol])

dnl no compiler optimization
CXXFLAGS=""

builddir=`pwd`

dnl check system architecture
AC_CANONICAL_HOST
case "${host_cpu}" in
x86_64)
    AC_DEFINE([CPU_64], [1], [64 Bit CPU])
    ;;
i386|i586|i686)
    AC_DEFINE([CPU_32], [1], [32 Bit CPU])
    ;;
*)
    AC_MSG_ERROR([unsupported build architecture. sorry...])
    ;;
esac


dnl check for python
AC_PATH_PROG(python_path, python)
AC_SUBST(PYTHON)
PYTHON=$python_path

if test ! -x $python_path
then
    AC_MSG_ERROR([no python interpreter found])
fi
AC_DEFINE_UNQUOTED(PYTHON,"$python_path",[Python interpreter])

dnl prepare scriptfiles
if test ! $(head -1 scripts/wolper-mcp.py | grep "${python_path}") 
then
	echo -n "setting python path in python-scripts... "
	sed -i "1 i\\#\!${python_path}" $builddir/data/create_db.py
	sed -i "1 i\\#\!${python_path}" $builddir/scripts/wolper-mcp.py
	echo "done"
fi

dnl check if database needs to be generated
AC_MSG_CHECKING(for wolpertinger.db)
if test -f "$builddir/data/wolpertinger.db"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
	echo -n "generating wolpertinger.db... "
	$builddir/data/create_db.py $builddir/data &> /dev/null
	echo "done"
fi

AC_OUTPUT([
Makefile
data/Makefile
docs/Makefile
scripts/Makefile
src/Makefile
])
