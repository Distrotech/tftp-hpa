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
dnl PA_BSD_SIGNAL()
dnl
dnl Test for BSD signal semantics.  Set shell variable BSD_SIGNAL=1 if OK.
dnl May modify CFLAGS and/or LIBS.
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_CHECK_BSD_SIGNAL,
[AC_TRY_RUN([
#include <unistd.h>
#include <signal.h>
int count=0;
handle() { count++; }
int main() {
    int pid=getpid();
    signal(SIGINT, handle);
    kill(pid,SIGINT);
    kill(pid,SIGINT);
    kill(pid,SIGINT);
    if (count!=3) return 1;
    return 0;
}
], BSD_SIGNAL=1)])

AC_DEFUN(PA_BSD_SIGNAL,
[AC_MSG_CHECKING([for BSD signal semantics])
PA_CHECK_BSD_SIGNAL()
if test -z "$BSD_SIGNAL"; then
  AC_MSG_RESULT([no])
  AC_MSG_CHECKING([if -D__USE_BSD_SIGNAL helps])
  pa_bsd_signal__old_cflags="$CFLAGS"
  CFLAGS="$CFLAGS -D__USE_BSD_SIGNAL"
  PA_CHECK_BSD_SIGNAL()
  if test -z "$BSD_SIGNAL"; then
    AC_MSG_RESULT([no])
    CFLAGS="$pa_bsd_signal__old_cflags"
    AC_MSG_CHECKING([if -lbsd helps])
    pa_bsd_signal__old_libs="$LIBS"
    LIBS="$LIBS -lbsd"
    PA_CHECK_BSD_SIGNAL()
    if test -z "$BSD_SIGNAL"; then
      AC_MSG_RESULT([no])
      LIBS="$pa_bsd_signal__old_libs"
    else
      AC_MSG_RESULT([yes])
    fi
  else
    AC_MSG_RESULT([yes])
  fi
else
  AC_MSG_RESULT([yes])
fi
])
