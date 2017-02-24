AC_INIT(authconfig, 7.0.0)
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip])
AC_PREFIX_DEFAULT(/usr)
AC_PROG_CC
AM_GLIB_GNU_GETTEXT
AM_PROG_LIBTOOL
AC_PROG_INTLTOOL

GETTEXT_PACKAGE='$(PACKAGE)'
AC_SUBST(GETTEXT_PACKAGE)

AC_CHECK_HEADERS(netinet/in.h arpa/nameser.h resolv.h,,)

AC_CHECK_FUNC(res_init,,[AC_CHECK_LIB(resolv,res_init,,[
 AC_CHECK_LIB(resolv,__res_init,,)])])

AC_ARG_WITH(python-rev,
            [  --with-python-rev=3    version of python for which modules should be built],
            PYTHONREV=$withval,[PYTHONREV=3])
AC_MSG_CHECKING([python version])
PYTHONREV=`python${PYTHONREV} -c 'import sys;print("%s.%s" % (sys.version_info[[0]], sys.version_info[[1]]))'`
AC_MSG_RESULT($PYTHONREV)
AC_SUBST(PYTHONREV)

AC_MSG_CHECKING(python includes)
INCLUDEPY=`python${PYTHONREV} -c 'import sysconfig;print(sysconfig.get_config_var("INCLUDEPY"))'`
AC_MSG_RESULT($INCLUDEPY)
PYTHON_CFLAGS=-I$INCLUDEPY
AC_SUBST(PYTHON_CFLAGS)

if test x$GCC = xyes ; then
	CFLAGS="${CFLAGS} -Wall"
	CFLAGS="${CFLAGS} -Wunused"
	CFLAGS="${CFLAGS} -Wuninitialized"
	CFLAGS="${CFLAGS} -Wimplicit"
	CFLAGS="${CFLAGS} -Wstrict-prototypes"
	CFLAGS="${CFLAGS} -Wmissing-prototypes"
	CFLAGS="${CFLAGS} -Wmissing-declarations"
	CFLAGS="${CFLAGS} -Wcast-align"
fi

AM_CONFIG_HEADER(config.h)

AC_OUTPUT([
Makefile
man/Makefile
man/en/Makefile
po/Makefile.in
authconfig.spec
])
