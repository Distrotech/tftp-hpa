dnl $Id$
dnl  -----------------------------------------------------------------------
dnl    
dnl    Copyright 1999-2002 H. Peter Anvin - All Rights Reserved
dnl 
dnl    This program is free software; you can redistribute it and/or modify
dnl    it under the terms of the GNU General Public License as published by
dnl    the Free Software Foundation, Inc., 53 Temple Place Ste 330,
dnl    Bostom MA 02111-1307, USA; either version 2 of the License, or
dnl    (at your option) any later version; incorporated herein by reference.
dnl 
dnl  -----------------------------------------------------------------------

dnl --------------------------------------------------------------------------
dnl PA_ADD_CFLAGS()
dnl
dnl Attempt to add the given option to CFLAGS, if it doesn't break compilation
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_ADD_CFLAGS,
[AC_MSG_CHECKING([if $CC accepts $1])
 pa_add_cflags__old_cflags="$CFLAGS"
 CFLAGS="$CFLAGS $1"
 AC_TRY_LINK([#include <stdio.h>],
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
 AC_TRY_LINK([
#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif],
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
AH_TEMPLATE([HAVE_MSGHDR_MSG_CONTROL],
[Define if struct msghdr has the msg_control field.])

AC_DEFUN(PA_MSGHDR_MSG_CONTROL,
 [AC_CHECK_MEMBER(struct msghdr.msg_control,
  [AC_DEFINE(HAVE_MSGHDR_MSG_CONTROL)],
  [],
  [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
  ])])

dnl ------------------------------------------------------------------------
dnl  PA_STRUCT_IN_PKTINFO
dnl 
dnl Look for definition of struct in_pktinfo, which at least has an
dnl ipi_addr member.  Some versions of glibc lack struct in_pktinfo;
dnl if so we need to include the definition ourselves -- but we only
dnl want to do that if absolutely necessary!
dnl
dnl We don't use AC_CHECK_MEMBER() here, since at least in autoconf 2.52
dnl this is broken for a member of structure type.
dnl ------------------------------------------------------------------------
AH_TEMPLATE([HAVE_STRUCT_IN_PKTINFO],
[Define if struct in_pktinfo is defined.])

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
	AC_MSG_RESULT(yes)
   ],
   [
	AC_MSG_RESULT(no)
   ])])

dnl --------------------------------------------------------------------------
dnl PA_HAVE_TCPWRAPPERS
dnl
dnl Do we have the tcpwrappers -lwrap?  This can't be done using AC_CHECK_LIBS
dnl due to the need to provide "allow_severity" and "deny_severity" variables
dnl --------------------------------------------------------------------------
AH_TEMPLATE([HAVE_TCPWRAPPERS],
[Define if we have tcpwrappers (-lwrap) and <tcpd.h>.])

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
dnl  PA_CHECK_INTTYPES_H_SANE
dnl
dnl  At least some versions of AIX 4 have <inttypes.h> macros which are
dnl  completely broken.  Try to detect those.
dnl --------------------------------------------------------------------------
AH_TEMPLATE([INTTYPES_H_IS_SANE],
[Define if the macros in <inttypes.h> are usable])

AC_DEFUN(PA_CHECK_INTTYPES_H_SANE,
[AC_CHECK_HEADERS(inttypes.h,
 [
  AC_MSG_CHECKING([if inttypes.h is sane])
  AC_TRY_LINK(
  [
#include <inttypes.h>
#include <stdio.h>
  ],
  [uintmax_t max = UINTMAX_C(0);
   printf("%"PRIuMAX"\n", max);],
  AC_MSG_RESULT([yes])
  AC_DEFINE(INTTYPES_H_IS_SANE),
  AC_MSG_RESULT([no (AIX, eh?)]))
 ])
])

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

dnl --------------------------------------------------------------------------
dnl  PA_HEADER_DEFINES
dnl
dnl  PA_HEADER_DEFINES(header, type, value)
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_HEADER_DEFINES,
[AC_MSG_CHECKING([if $1 defines $3])
 AH_TEMPLATE([HAVE_$3_DEFINITION], [Define if $1 defines $3])
 AC_TRY_COMPILE([
#include <$1>
],
[
int main()
{
	$2 dummy = $3;
	return 0;
}
],
[
 pa_header_define=`echo HAVE_$3_DEFINITION | tr '[a-z]' '[A-Z]'`
 AC_DEFINE_UNQUOTED($pa_header_define)
 AC_MSG_RESULT(yes)
],
[
 AC_MSG_RESULT(no)
])])
