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
dnl Do we have sigsetjmp/siglongjmp?
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_SIGSETJMP,
[AC_MSG_CHECKING([for sigsetjmp])
 AC_TRY_LINK(
 [#include <setjmp.h>],
 [sigjmp_buf buf;
  sigsetjmp(buf,1);],
 AC_MSG_RESULT([yes])
 $1,
 AC_MSG_RESULT([no])
 $2)])
