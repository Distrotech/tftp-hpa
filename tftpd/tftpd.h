/* $Id$ */
/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 2001 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software available under the same license
 *   as the "OpenBSD" operating system, distributed at
 *   http://www.openbsd.org/.
 *
 * ----------------------------------------------------------------------- */

/*
 * tftpd.h
 *
 * Prototypes for various functions that are part of the tftpd server.
 */

#ifndef TFTPD_TFTPD_H
#define TFTPD_TFTPD_H

#include <stdlib.h>
#include <stdio.h>
#include "../config.h"
#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#else
#define EX_USAGE        64      /* command line usage error */
#define EX_DATAERR      65      /* data format error */
#define EX_NOINPUT      66      /* cannot open input */
#define EX_NOUSER       67      /* addressee unknown */
#define EX_NOHOST       68      /* host name unknown */
#define EX_UNAVAILABLE  69      /* service unavailable */
#define EX_SOFTWARE     70      /* internal software error */
#define EX_OSERR        71      /* system error (e.g., can't fork) */
#define EX_OSFILE       72      /* critical OS file missing */
#define EX_CANTCREAT    73      /* can't create (user) output file */
#define EX_IOERR        74      /* input/output error */
#define EX_TEMPFAIL     75      /* temp failure; user is invited to retry */
#define EX_PROTOCOL     76      /* remote error in protocol */
#define EX_NOPERM       77      /* permission denied */
#define EX_CONFIG       78      /* configuration error */
#endif

#ifndef HAVE_SIGSETJMP
#define sigsetjmp(x,y)  setjmp(x)
#define siglongjmp(x,y) longjmp(x,y)
#define sigjmp_buf jmp_buf
#endif

void set_signal(int, void (*)(int), int);
void *tfmalloc(size_t);
char *tfstrdup(const char *);

extern int verbosity;

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#endif
