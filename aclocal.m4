dnl --------------------------------------------------------------------------
dnl PA_ADD_CFLAGS()
dnl
dnl Attempt to add the given option to CFLAGS, if it doesn't break compilation
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_ADD_CFLAGS,
[AC_MSG_CHECKING([if $CC accepts $1])
 pa_add_cflags__old_cflags="$CFLAGS"
 CFLAGS="$CFLAGS $1"
 AC_TRY_COMPILE([#include <stdio.h>],
 [printf("Hello, World!\n");],
 AC_MSG_RESULT([yes]),
 AC_MSG_RESULT([no])
 CFLAGS="$pa_add_cflags__old_cflags")])

dnl --------------------------------------------------------------------------
dnl PA_SIGSETJMP
dnl
dnl Do we have sigsetjmp/siglongjmp?  (AC_CHECK_FUNCS doesn't seem to work
dnl for these particular functions.)
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_SIGSETJMP,
[AC_MSG_CHECKING([for sigsetjmp])
 AC_TRY_LINK(
 [#include <setjmp.h>],
 [sigjmp_buf buf;
  sigsetjmp(buf,1);
  siglongjmp(buf,2);],
 AC_MSG_RESULT([yes])
 $1,
 AC_MSG_RESULT([no])
 $2)])

dnl --------------------------------------------------------------------------
dnl PA_MSGHDR_MSG_CONTROL
dnl
dnl Does struct msghdr have the msg_control field?
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_MSGHDR_MSG_CONTROL,
[AC_MSG_CHECKING([for msg_control in struct msghdr])
 AC_TRY_COMPILE(
[
#include <sys/types.h>
#include <sys/socket.h>
],
[
        struct msghdr msg;
        void *p = (void *) &msg.msg_control;
],
[
        AC_DEFINE(HAVE_MSGHDR_MSG_CONTROL)
        AC_MSG_RESULT([yes])
],
[
        AC_MSG_RESULT([no])
])])

dnl ------------------------------------------------------------------------
dnl  PA_STRUCT_IN_PKTINFO
dnl
dnl Look for definition of struct in_pktinfo.  Some versions of glibc
dnl lack struct in_pktinfo; if so we need to include the definition
dnl ourselves -- but we only want to do that if absolutely necessary!
dnl ------------------------------------------------------------------------
AC_DEFUN(PA_STRUCT_IN_PKTINFO,
[AC_MSG_CHECKING([for definition of struct in_pktinfo])
 AC_TRY_COMPILE(
[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/uio.h>
],
[
	struct in_pktinfo pktinfo;
	int foo = sizeof(struct in_pktinfo);
	void *quux = (void *)(&pktinfo.ipi_addr);
],
[
        AC_DEFINE(HAVE_STRUCT_IN_PKTINFO)
        AC_MSG_RESULT([yes])
],
[
        AC_MSG_RESULT([no])
])])

dnl --------------------------------------------------------------------------
dnl PA_HAVE_TCPWRAPPERS
dnl
dnl Do we have the tcpwrappers -lwrap?  This can't be done using AC_CHECK_LIBS
dnl due to the need to provide "allow_severity" and "deny_severity" variables
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_HAVE_TCPWRAPPERS,
[AC_CHECK_LIB([wrap], [main])
 AC_MSG_CHECKING([for tcpwrappers])
 AC_TRY_LINK(
[
#include <tcpd.h>
int allow_severity = 0;
int deny_severity = 0;
],
[
	hosts_ctl("sample_daemon", STRING_UNKNOWN, STRING_UNKNOWN, STRING_UNKNOWN);
],
[
	AC_DEFINE(HAVE_TCPWRAPPERS)
	AC_MSG_RESULT([yes])
],
[
	AC_MSG_RESULT([no])
])])

dnl ------------------------------------------------------------------------
dnl  PA_WITH_BOOL
dnl
dnl  PA_WITH_BOOL(option, default, help, enable, disable)
dnl
dnl  Provides a more convenient way to specify --with-option and
dnl  --without-option, with a default.  default should be either 0 or 1.
dnl ------------------------------------------------------------------------
AC_DEFUN(PA_WITH_BOOL,
[AC_ARG_WITH([$1], [$3],
if test ["$withval"] != no; then
[$4]
else
[$5]
fi,
if test [$2] -ne 0; then
[$4]
else
[$5]
fi)])
