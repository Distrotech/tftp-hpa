/* tftp-hpa: $Id$ */

/* $OpenBSD: tftpd.c,v 1.13 1999/06/23 17:01:36 deraadt Exp $	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "tftpd.h"

#ifndef lint
static const char *copyright UNUSED =
"@(#) Copyright (c) 1983 Regents of the University of California.\n\
 All rights reserved.\n";
/*static char sccsid[] = "from: @(#)tftpd.c	5.13 (Berkeley) 2/26/91";*/
/*static char rcsid[] = "$OpenBSD: tftpd.c,v 1.13 1999/06/23 17:01:36 deraadt Exp $: tftpd.c,v 1.6 1997/02/16 23:49:21 deraadt Exp $";*/
static const char *rcsid UNUSED =
"tftp-hpa $Id$";
#endif /* not lint */

/*
 * Trivial file transfer protocol server.
 *
 * This version includes many modifications by Jim Guyton <guyton@rand-unix>
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/tftp.h>
#include <netdb.h>

#include <setjmp.h>
#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#define __USE_GNU		/* Necessary for basename() on glibc systems */
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>

#include "tftpsubs.h"
#include "recvfrom.h"
#include "remap.h"

#ifdef HAVE_TCPWRAPPERS
#include <tcpd.h>

int deny_severity	= LOG_WARNING;
int allow_severity	= -1;	/* Don't log at all */

struct request_info wrap_request;
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>		/* Necessary for basename() on Solaris */
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>		/* Necessary for FIONBIO on Solaris */
#endif

#define	TIMEOUT 5		/* Default timeout (seconds) */
#define TRIES   4		/* Number of attempts to send each packet */
#define TIMEOUT_LIMIT (TRIES*(TRIES+1)/2)

#ifndef OACK
#define OACK	6
#endif
#ifndef EOPTNEG
#define EOPTNEG	8
#endif

char   *__progname;
int	peer;
int	timeout    = TIMEOUT;
int	rexmtval   = TIMEOUT;
int	maxtimeout = TIMEOUT_LIMIT*TIMEOUT;

#define	PKTSIZE	MAX_SEGSIZE+4
char	buf[PKTSIZE];
char	ackbuf[PKTSIZE];
struct	sockaddr_in from;
int	fromlen;
off_t	tsize;
int     tsize_ok;

int	ndirs;
char	**dirs;

int	secure = 0;
int	cancreate = 0;

int verbosity = 0;

struct formats;
#ifdef WITH_REGEX
static struct rule *rewrite_rules = NULL;
#endif

int tftp(struct tftphdr *, int);
void nak(int);
void timer(int);
void justquit(int);
void do_opt(char *, char *, char **);

int set_blksize(char *, char **);
int set_blksize2(char *, char **);
int set_tsize(char *, char **);
int set_timeout(char *, char **);

struct options {
  char    *o_opt;
  int     (*o_fnc)(char *, char **);
} options[] = {
  { "blksize",    set_blksize  },
  { "blksize2",   set_blksize2  },
  { "tsize",      set_tsize },
  { "timeout",	set_timeout  },
  { NULL,         NULL }
};

/* Simple handler for SIGHUP */
static volatile sig_atomic_t caught_sighup = 0;
static void handle_sighup(int sig)
{
  (void)sig;			/* Suppress unused warning */
  caught_sighup = 1;
}


static void
usage(void)
{
  syslog(LOG_ERR, "Usage: %s [-vcl][-a address][-m mappings][-u user][-t timeout][-r option...] [-s] [directory ...]",
	 __progname);
  exit(EX_USAGE);
}


#ifdef WITH_REGEX
static struct rule *
read_remap_rules(const char *file)
{
  FILE *f;
  struct rule *rulep;

  f = fopen(file, "rt");
  if ( !f ) {
    syslog(LOG_ERR, "Cannot open map file: %s: %m", file);
    exit(EX_NOINPUT);
  }
  rulep = parserulefile(f);
  fclose(f);

  return rulep;
}
#endif

int
main(int argc, char **argv)
{
  struct tftphdr *tp;
  struct passwd *pw;
  struct options *opt;
  struct sockaddr_in myaddr;
  struct sockaddr_in bindaddr;
  int n = 0;
  int on = 1;
  int fd = 0;
  int listen = 0;		/* Standalone (listen) mode */
  char *address = NULL;		/* Address to listen to */
  int pid;
  int c;
  int setrv;
  int timeout = 900;		/* Default timeout */
  char *user = "nobody";	/* Default user */
#ifdef WITH_REGEX
  char *rewrite_file = NULL;
#endif

  __progname = basename(argv[0]);
  
  openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
  
  while ((c = getopt(argc, argv, "csvla:u:r:t:m:")) != -1)
    switch (c) {
    case 'c':
      cancreate = 1;
      break;
    case 's':
      secure = 1;
      break;
    case 'l':
      listen = 1;
      break;
    case 'a':
      address = optarg;
      break;
    case 't':
      timeout = atoi(optarg);
      break;
    case 'u':
      user = optarg;
      break;
    case 'r':
      for ( opt = options ; opt->o_opt ; opt++ ) {
	if ( !strcasecmp(optarg, opt->o_opt) ) {
	  opt->o_opt = ""; /* Don't support this option */
	  break;
	}
      }
      if ( !opt->o_opt ) {
	syslog(LOG_ERR, "Unknown option: %s", optarg);
	exit(EX_USAGE);
      }
      break;
#ifdef WITH_REGEX
    case 'm':
      if ( rewrite_file ) {
	syslog(LOG_ERR, "Multiple -m options");
	exit(EX_USAGE);
      }
      rewrite_file = optarg;
      break;
#endif
    case 'v':
      verbosity++;
      break;
    default:
      usage();
      break;
    }
  
  for (; optind != argc; optind++) {
    if (dirs)
      dirs = realloc(dirs, (ndirs+2) * sizeof (char *));
    else
      dirs = calloc(ndirs+2, sizeof(char *));
    if (dirs == NULL) {
      syslog(LOG_ERR, "malloc: %m");
      exit(EX_OSERR);
    }			
    dirs[n++] = argv[optind];
    dirs[n] = NULL;
    ndirs++;
  }
  
  if (secure) {
    if (ndirs == 0) {
      syslog(LOG_ERR, "no -s directory");
      exit(EX_USAGE);
    }
    if (ndirs > 1) {
      syslog(LOG_ERR, "too many -s directories");
      exit(EX_USAGE);
    }
    if (chdir(dirs[0])) {
      syslog(LOG_ERR, "%s: %m", dirs[0]);
      exit(EX_NOINPUT);
    }
  }
  
  pw = getpwnam(user);
  if (!pw) {
    syslog(LOG_ERR, "no user %s: %m", user);
    exit(EX_NOUSER);
  }
  
  if (ioctl(fd, FIONBIO, &on) < 0) {
    syslog(LOG_ERR, "ioctl(FIONBIO): %m");
    exit(EX_OSERR);
  }

#ifdef WITH_REGEX
  if ( rewrite_file )
    rewrite_rules = read_remap_rules(rewrite_file);
#endif

  /* If we're running standalone, set up the input port */
  if ( listen ) {
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    
    memset(&bindaddr, 0, sizeof bindaddr);
    bindaddr.sin_addr.s_addr = INADDR_ANY;
    bindaddr.sin_port = htons(IPPORT_TFTP);

    if ( address ) {
      char *portptr, *eportptr;
      struct hostent *hostent;
      struct servent *servent;
      unsigned long port;

      address = tfstrdup(address);
      portptr = strrchr(address, ':');
      if ( portptr )
	*portptr++ = '\0';
      
      if ( *address ) {
	hostent = gethostbyname(address);
	if ( !hostent || hostent->h_addrtype != AF_INET ) {
	  syslog(LOG_ERR, "cannot resolve local bind address: %s", address);
	  exit(EX_NOINPUT);
	}
	memcpy(&bindaddr.sin_addr, hostent->h_addr, hostent->h_length);
      } else {
	/* Default to using INADDR_ANY */
      }
    
      if ( portptr && *portptr ) {
	servent = getservbyname(portptr, "udp");
	if ( servent ) {
	  bindaddr.sin_port = servent->s_port;
	} else if ( (port = strtoul(portptr, &eportptr, 0)) && !*eportptr ) {
	  bindaddr.sin_port = htons(port);
	} else if ( !strcmp(portptr, "tftp") ) {
	  /* It's TFTP, we're OK */
	} else {
	  syslog(LOG_ERR, "cannot resolve local bind port: %s", portptr);
	  exit(EX_NOINPUT);
	}
      }
    }

    if (bind(fd, (struct sockaddr *)&bindaddr, sizeof bindaddr) < 0) {
      syslog(LOG_ERR, "cannot bind to local socket: %m");
      exit(EX_OSERR);
    }

    /* Daemonize this process */
    {
      int f = fork();
      if ( f > 0 )
	exit(0);
      if ( f < 0 ) {
	syslog(LOG_ERR, "cannot fork: %m");
	exit(EX_OSERR);
      }
      close(0); close(1); close(2);
#ifdef HAVE_SETSID
      setsid();
#endif
    }
  } else {
    /* 0 is our socket descriptor */
    close(1); close(2);
  }

  /* This means we don't want to wait() for children */
  set_signal(SIGCHLD, SIG_IGN, SA_NOCLDSTOP);
  
  /* Take SIGHUP and use it to set a variable.  This
     is polled synchronously to make sure we don't
     lose packets as a result. */
  set_signal(SIGHUP, handle_sighup, 0);
  
  while ( 1 ) {
    fd_set readset;
    struct timeval tv_timeout;
    int rv;
    
    if ( caught_sighup ) {
      caught_sighup = 0;
      if ( listen ) {
#ifdef HAVE_REGEX
	if ( rewrite_file ) {
	  freerules(rewrite_rules);
	  rewrite_rules = read_remap_rules(rewrite_file);
	}
#endif
      } else {
	/* Return to inetd for respawn */
	exit(0);
      }
    }
    
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    tv_timeout.tv_sec = timeout;
    tv_timeout.tv_usec = 0;
    
    /* Never time out if we're in listen mode */
    rv = select(fd+1, &readset, NULL, NULL, listen ? NULL : &tv_timeout);
    if ( rv == -1 && errno == EINTR )
      continue;		/* Signal caught, reloop */
    if ( rv == -1 ) {
      syslog(LOG_ERR, "select loop: %m");
      exit(EX_OSERR);
    } else if ( rv == 0 ) {
      exit(0);		/* Timeout, return to inetd */
    }
    
    fromlen = sizeof (from);
    n = myrecvfrom(fd, buf, sizeof (buf), 0,
		   (struct sockaddr *)&from, &fromlen,
		   &myaddr);

    if ( listen && myaddr.sin_addr.s_addr == INADDR_ANY ) {
      /* myrecvfrom() didn't capture the source address; but we might
	 have bound to a specific address, if so we should use it */
      memcpy(&myaddr.sin_addr, &bindaddr.sin_addr, sizeof bindaddr.sin_addr);
    }

    if (n < 0) {
      syslog(LOG_ERR, "recvfrom: %m");
      exit(EX_IOERR);
    }
    
    /*
     * Now that we have read the request packet from the UDP
     * socket, we fork and go back to listening to the socket.
     */
    pid = fork();
    if (pid < 0) {
      syslog(LOG_ERR, "fork: %m");
      exit(EX_OSERR);	/* Return to inetd, just in case */
    } else if ( pid == 0 )
      break;			/* Child exit, parent loop */
  }
  
  /* Child process: handle the actual request here */
  
  /* Ignore SIGHUP */
  set_signal(SIGHUP, SIG_IGN, 0);
  
#ifdef HAVE_TCPWRAPPERS
  /* Verify if this was a legal request for us.  This has to be
     done before the chroot, while /etc is still accessible. */
  request_init(&wrap_request,
	       RQ_DAEMON, __progname,
	       RQ_FILE, fd,
	       RQ_CLIENT_SIN, &from,
	       RQ_SERVER_SIN, &myaddr,
	       0);
  sock_methods(&wrap_request);
  if ( hosts_access(&wrap_request) == 0 ) {
    if ( deny_severity != -1 )
      syslog(deny_severity, "connection refused from %s",
	     inet_ntoa(from.sin_addr));
    exit(EX_NOPERM);	/* Access denied */
  } else if ( allow_severity != -1 ) {
    syslog(allow_severity, "connect from %s",
	   inet_ntoa(from.sin_addr));
  }
#endif

  /* Close file descriptors we don't need */
  close(fd);
  
  /* Get a socket.  This has to be done before the chroot(), since
     some systems require access to /dev to create a socket. */
  
  peer = socket(AF_INET, SOCK_DGRAM, 0);
  if (peer < 0) {
    syslog(LOG_ERR, "socket: %m");
    exit(EX_IOERR);
  }

  /* Chroot and drop privileges */
  
  if (secure && chroot(".")) {
    syslog(LOG_ERR, "chroot: %m");
    exit(EX_OSERR);
  }
  
#ifdef HAVE_SETREGID
  setrv = setregid(pw->pw_gid, pw->pw_gid);
#else
  setrv = setegid(pw->pw_gid) || setgid(pw->pw_gid);
#endif
  
#ifdef HAVE_SETREUID
  setrv = setrv || setreuid(pw->pw_uid, pw->pw_uid);
#else
  /* Important: setuid() must come first */
  setrv = setrv || setuid(pw->pw_uid) ||
    (geteuid() != pw->pw_uid && seteuid(pw->pw_uid));
#endif
  
  if ( setrv ) {
    syslog(LOG_ERR, "cannot drop privileges: %m");
    exit(EX_OSERR);
  }
  
  /* Other basic setup */
  from.sin_family = AF_INET;
  alarm(0);
  
  /* Process the request... */
  
  myaddr.sin_port = htons(0); /* We want a new local port */
  if (bind(peer, (struct sockaddr *)&myaddr, sizeof myaddr) < 0) {
    syslog(LOG_ERR, "bind: %m");
    exit(EX_IOERR);
  }
  if (connect(peer, (struct sockaddr *)&from, sizeof from) < 0) {
    syslog(LOG_ERR, "connect: %m");
    exit(EX_IOERR);
  }
  tp = (struct tftphdr *)buf;
  tp->th_opcode = ntohs(tp->th_opcode);
  if (tp->th_opcode == RRQ || tp->th_opcode == WRQ)
    tftp(tp, n);
  exit(0);
}

char   *rewrite_access(char *, int);
int	validate_access(char *, int, struct formats *);
void	sendfile(struct formats *, struct tftphdr *, int);
void	recvfile(struct formats *, struct tftphdr *, int);

struct formats {
  char	*f_mode;
  char	*(*f_rewrite)(char *, int);
  int	(*f_validate)(char *, int, struct formats *);
  void	(*f_send)(struct formats *, struct tftphdr *, int);
  void	(*f_recv)(struct formats *, struct tftphdr *, int);
  int	f_convert;
} formats[] = {
  { "netascii",   rewrite_access, validate_access, sendfile, recvfile, 1 },
  { "octet",	rewrite_access, validate_access, sendfile, recvfile, 0 },
  { NULL, NULL, NULL, NULL, NULL, 0 }
};

/*
 * Handle initial connection protocol.
 */
int
tftp(struct tftphdr *tp, int size)
{
  char *cp;
  int argn, ecode;
  struct formats *pf = NULL;
  char *origfilename;
  char *filename, *mode = NULL;
  
  char *val = NULL, *opt = NULL;
  char *ap = ackbuf + 2;
  
  ((struct tftphdr *)ackbuf)->th_opcode = ntohs(OACK);
  
  origfilename = cp = (char *) &(tp->th_stuff);
  argn = 0;
  
  while ( cp < buf + size && *cp ) {
    do {
      cp++;
    } while (cp < buf + size && *cp);
    
    if ( *cp ) {
      nak(EBADOP);	/* Corrupt packet - no final NULL */
      exit(0);
    }
    
    argn++;
    if (argn == 1) {
      mode = ++cp;
    } else if (argn == 2) {
      for (cp = mode; *cp; cp++)
	*cp = tolower(*cp);
      for (pf = formats; pf->f_mode; pf++) {
	if (!strcmp(pf->f_mode, mode))
	  break;
      }
      if (!pf->f_mode) {
	nak(EBADOP);
	exit(0);
      }
      if ( !(filename = (*pf->f_rewrite)(origfilename, tp->th_opcode)) ) {
	nak(EACCESS); /* File denied by mapping rule */
	exit(0);
      }
      if ( verbosity >= 1 ) {
	if ( filename == origfilename || !strcmp(filename, origfilename) )
	  syslog(LOG_NOTICE, "%s from %s filename %s\n",
		 tp->th_opcode == WRQ ? "WRQ" : "RRQ",
		 inet_ntoa(from.sin_addr), filename);
	else
	  syslog(LOG_NOTICE, "%s from %s filename %s remapped to %s\n",
		 tp->th_opcode == WRQ ? "WRQ" : "RRQ",
		 inet_ntoa(from.sin_addr), origfilename, filename);
      }		   
      ecode = (*pf->f_validate)(filename, tp->th_opcode, pf);
      if (ecode) {
	nak(ecode);
	exit(0);
      }
      opt = ++cp;
    } else if ( argn & 1 ) {
      val = ++cp;
    } else {
      do_opt(opt, val, &ap);
      opt = ++cp;
    }
  }
  
  if (!pf) {
    nak(EBADOP);
    exit(0);
  }
  
  if ( ap != (ackbuf+2) ) {
    if ( tp->th_opcode == WRQ )
      (*pf->f_recv)(pf, (struct tftphdr *)ackbuf, ap-ackbuf);
    else
      (*pf->f_send)(pf, (struct tftphdr *)ackbuf, ap-ackbuf);
  } else {
    if (tp->th_opcode == WRQ)
      (*pf->f_recv)(pf, NULL, 0);
    else
      (*pf->f_send)(pf, NULL, 0);
  }
  exit(0);			/* Request completed */
}

static int blksize_set;

/*
 * Set a non-standard block size (c.f. RFC2348)
 */
int
set_blksize(char *val, char **ret)
{
  static char b_ret[6];
  unsigned int sz = atoi(val);
  
  if ( blksize_set )
    return 0;
  
  if (sz < 8)
    return(0);
  else if (sz > MAX_SEGSIZE)
    sz = MAX_SEGSIZE;
  
  segsize = sz;
  sprintf(*ret = b_ret, "%u", sz);
  
  blksize_set = 1;
  
  return(1);
}

/*
 * Set a power-of-two block size (nonstandard)
 */
int
set_blksize2(char *val, char **ret)
{
  static char b_ret[6];
  unsigned int sz = atoi(val);
  
  if ( blksize_set )
    return 0;
  
  if (sz < 8)
    return(0);
  else if (sz > MAX_SEGSIZE)
    sz = MAX_SEGSIZE;
  
  /* Convert to a power of two */
  if ( sz & (sz-1) ) {
    unsigned int sz1 = 1;
    /* Not a power of two - need to convert */
    while ( sz >>= 1 )
      sz1 <<= 1;
    sz = sz1;
  }
  
  segsize = sz;
  sprintf(*ret = b_ret, "%u", sz);
  
  blksize_set = 1;
  
  return(1);
}

/*
 * Return a file size (c.f. RFC2349)
 * For netascii mode, we don't know the size ahead of time;
 * so reject the option.
 */
int
set_tsize(char *val, char **ret)
{
  static char b_ret[sizeof(off_t)*CHAR_BIT/3+2];
  off_t sz = atol(val);
  
  if ( !tsize_ok )
    return 0;
  
  if (sz == 0)
    sz = tsize;
  sprintf(*ret = b_ret, "%lu", sz);
  return(1);
}

/*
 * Set the timeout (c.f. RFC2349)
 */
int
set_timeout(char *val, char **ret)
{
  static char b_ret[4];
  unsigned long to = atol(val);
  
  if ( to < 1 || to > 255 )
    return 0;
  
  timeout    = to;
  rexmtval   = to;
  maxtimeout = TIMEOUT_LIMIT*to;
  
  sprintf(*ret = b_ret, "%lu", to);
  return(1);
}

/*
 * Parse RFC2347 style options
 */
void
do_opt(char *opt, char *val, char **ap)
{
  struct options *po;
  char *ret;
  
  /* Global option-parsing variables initialization */
  blksize_set = 0;
  
  if ( !*opt )
    return;
  
  for (po = options; po->o_opt; po++)
    if (!strcasecmp(po->o_opt, opt)) {
      if (po->o_fnc(val, &ret)) {
	if (*ap + strlen(opt) + strlen(ret) + 2 >=
	    ackbuf + sizeof(ackbuf)) {
	  nak(ENOSPACE);	/* EOPTNEG? */
	  exit(0);
	}
	*ap = strrchr(strcpy(strrchr(strcpy(*ap, opt),'\0') + 1,
			     ret),'\0') + 1;
      } else {
	nak(EOPTNEG);
	exit(0);
      }
      break;
    }
  return;
}

/*
 * Modify the filename, if applicable.  If it returns NULL, deny the access.
 */
char *
rewrite_access(char *filename, int mode)
{
#ifdef WITH_REGEX
  if ( rewrite_rules ) {
    char *newname = rewrite_string(filename, rewrite_rules, mode != RRQ);
    filename = newname;
  }
#else
  (void)mode;			/* Suppress unused warning */
#endif
  return filename;
}

FILE *file;
/*
 * Validate file access.  Since we
 * have no uid or gid, for now require
 * file to exist and be publicly
 * readable/writable.
 * If we were invoked with arguments
 * from inetd then the file must also be
 * in one of the given directory prefixes.
 * Note also, full path name must be
 * given as we have no login directory.
 */
int
validate_access(char *filename, int mode, struct formats *pf)
{
  struct stat stbuf;
  int	fd, wmode;
  char *cp, **dirp;
  
  tsize_ok = 0;
  
  if (!secure) {
    if (*filename != '/')
      return (EACCESS);
    /*
     * prevent tricksters from getting around the directory
     * restrictions
     */
    for (cp = filename + 1; *cp; cp++)
      if(*cp == '.' && strncmp(cp-1, "/../", 4) == 0)
	return(EACCESS);
    for (dirp = dirs; *dirp; dirp++)
      if (strncmp(filename, *dirp, strlen(*dirp)) == 0)
	break;
    if (*dirp==0 && dirp!=dirs)
      return (EACCESS);
  }
  
  /*
   * We use different a different permissions scheme if `cancreate' is
   * set.
   */
  wmode = O_TRUNC;
  if (stat(filename, &stbuf) < 0) {
    if (!cancreate)
      return (errno == ENOENT ? ENOTFOUND : EACCESS);
    else {
      if ((errno == ENOENT) && (mode != RRQ))
	wmode |= O_CREAT;
      else
	return(EACCESS);
    }
  } else {
    if (mode == RRQ) {
      if ((stbuf.st_mode&(S_IREAD >> 6)) == 0)
	return (EACCESS);
      tsize = stbuf.st_size;
      /* We don't know the tsize if conversion is needed */
      tsize_ok = !pf->f_convert;
    } else {
      if ((stbuf.st_mode&(S_IWRITE >> 6)) == 0)
	return (EACCESS);
      tsize = 0;
      tsize_ok = 1;
    }
  }
  fd = open(filename, mode == RRQ ? O_RDONLY : (O_WRONLY|wmode), 0666);
  if (fd < 0)
    return (errno + 100);
  /*
   * If the file was created, set default permissions.
   */
  if ((wmode & O_CREAT) && fchmod(fd, 0666) < 0) {
    int serrno = errno;
    
    close(fd);
    unlink(filename);
    
    return (serrno + 100);
  }
  file = fdopen(fd, (mode == RRQ)? "r":"w");
  if (file == NULL)
    return (errno + 100);
  return (0);
}

int	timeout;
sigjmp_buf	timeoutbuf;

/* Handle timeout signal */
void
timer(int sig)
{
  (void)sig;			/* Suppress unused warning */
  timeout += rexmtval;
  if (timeout >= maxtimeout)
    exit(0);
  siglongjmp(timeoutbuf, 1);
}

/*
 * Send the requested file.
 */
void
sendfile(struct formats *pf, struct tftphdr *oap, int oacklen)
{
  struct tftphdr *dp;
  struct tftphdr *ap;		/* ack packet */
  static int block = 1;		/* Static to avoid longjmp funnies */
  int size, n;
  
  ap = (struct tftphdr *)ackbuf;
  
  if (oap) {
    timeout = 0;
    (void)sigsetjmp(timeoutbuf,1);
  oack:
    if (send(peer, oap, oacklen, 0) != oacklen) {
      syslog(LOG_ERR, "tftpd: oack: %m\n");
      goto abort;
    }
    for ( ; ; ) {
      set_signal(SIGALRM, timer, SA_RESTART);
      alarm(rexmtval);
      n = recv(peer, ackbuf, sizeof(ackbuf), 0);
      alarm(0);
      if (n < 0) {
	syslog(LOG_ERR, "tftpd: read: %m\n");
	goto abort;
      }
      ap->th_opcode = ntohs((u_short)ap->th_opcode);
      ap->th_block = ntohs((u_short)ap->th_block);
      
      if (ap->th_opcode == ERROR) {
	syslog(LOG_ERR, "tftp: client does not accept "
	       "options\n");
	goto abort;
      }
      if (ap->th_opcode == ACK) {
	if (ap->th_block == 0)
	  break;
	/* Resynchronize with the other side */
	(void)synchnet(peer);
	goto oack;
      }
    }
  }

  dp = r_init();
  do {
    size = readit(file, &dp, pf->f_convert);
    if (size < 0) {
      nak(errno + 100);
      goto abort;
    }
    dp->th_opcode = htons((u_short)DATA);
    dp->th_block = htons((u_short)block);
    timeout = 0;
    (void) sigsetjmp(timeoutbuf,1);
    
  send_data:
    if (send(peer, dp, size + 4, 0) != size + 4) {
      syslog(LOG_ERR, "tftpd: write: %m");
      goto abort;
    }
    read_ahead(file, pf->f_convert);
    for ( ; ; ) {
      set_signal(SIGALRM, timer, SA_RESTART);
      alarm(rexmtval);	/* read the ack */
      n = recv(peer, ackbuf, sizeof (ackbuf), 0);
      alarm(0);
      if (n < 0) {
	syslog(LOG_ERR, "tftpd: read(ack): %m");
	goto abort;
      }
      ap->th_opcode = ntohs((u_short)ap->th_opcode);
      ap->th_block = ntohs((u_short)ap->th_block);
      
      if (ap->th_opcode == ERROR)
	goto abort;
      
      if (ap->th_opcode == ACK) {
	if (ap->th_block == block) {
	  break;
	}
				/* Re-synchronize with the other side */
	(void) synchnet(peer);
	if (ap->th_block == (block -1)) {
	  goto send_data;
	}
      }
      
    }
    block++;
  } while (size == segsize);
 abort:
  (void) fclose(file);
}

/* Bail out signal handler */
void
justquit(int sig)
{
  (void)sig;			/* Suppress unused warning */
  exit(0);
}


/*
 * Receive a file.
 */
void
recvfile(struct formats *pf, struct tftphdr *oap, int oacklen)
{
  struct tftphdr *dp;
  int n, size;
  /* These are "static" to avoid longjmp funnies */
  static struct tftphdr *ap;    /* ack buffer */
  static int block = 0, acksize;
  
  dp = w_init();
  do {
    timeout = 0;
    
    if (!block && oap) {
      ap = (struct tftphdr *)ackbuf;
      acksize = oacklen;
    } else {
      ap = (struct tftphdr *)ackbuf;
      ap->th_opcode = htons((u_short)ACK);
      ap->th_block = htons((u_short)block);
      acksize = 4;
    }
    block++;
    (void) sigsetjmp(timeoutbuf,1);
    set_signal(SIGALRM, timer, SA_RESTART);
  send_ack:
    if (send(peer, ackbuf, acksize, 0) != acksize) {
      syslog(LOG_ERR, "tftpd: write(ack): %m");
      goto abort;
    }
    write_behind(file, pf->f_convert);
    for ( ; ; ) {
      set_signal(SIGALRM, timer, SA_RESTART);
      alarm(rexmtval);
      n = recv(peer, dp, PKTSIZE, 0);
      alarm(0);
      if (n < 0) {		/* really? */
	syslog(LOG_ERR, "tftpd: read: %m");
	goto abort;
      }
      dp->th_opcode = ntohs((u_short)dp->th_opcode);
      dp->th_block = ntohs((u_short)dp->th_block);
      if (dp->th_opcode == ERROR)
	goto abort;
      if (dp->th_opcode == DATA) {
	if (dp->th_block == block) {
	  break;   /* normal */
	}
				/* Re-synchronize with the other side */
	(void) synchnet(peer);
	if (dp->th_block == (block-1))
	  goto send_ack;		/* rexmit */
      }
    }
    /*  size = write(file, dp->th_data, n - 4); */
    size = writeit(file, &dp, n - 4, pf->f_convert);
    if (size != (n-4)) {			/* ahem */
      if (size < 0) nak(errno + 100);
      else nak(ENOSPACE);
      goto abort;
    }
  } while (size == segsize);
  write_behind(file, pf->f_convert);
  (void) fclose(file);		/* close data file */
  
  ap->th_opcode = htons((u_short)ACK);    /* send the "final" ack */
  ap->th_block = htons((u_short)(block));
  (void) send(peer, ackbuf, 4, 0);
  
  set_signal(SIGALRM, justquit, SA_RESETHAND); /* just quit on timeout */
  alarm(rexmtval);
  n = recv(peer, buf, sizeof (buf), 0); /* normally times out and quits */
  alarm(0);
  if (n >= 4 &&			/* if read some data */
      dp->th_opcode == DATA &&    /* and got a data block */
      block == dp->th_block) {	/* then my last ack was lost */
    (void) send(peer, ackbuf, 4, 0);     /* resend final ack */
  }
 abort:
  return;
}

struct errmsg {
  int	e_code;
  char	*e_msg;
} errmsgs[] = {
  { EUNDEF,	"Undefined error code" },
  { ENOTFOUND,	"File not found" },
  { EACCESS,	"Access violation" },
  { ENOSPACE,	"Disk full or allocation exceeded" },
  { EBADOP,	"Illegal TFTP operation" },
  { EBADID,	"Unknown transfer ID" },
  { EEXISTS,	"File already exists" },
  { ENOUSER,	"No such user" },
  { EOPTNEG,	"Failure to negotiate RFC2347 options" },
  { -1,		0 }
};

/*
 * Send a nak packet (error message).
 * Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno
 * offset by 100.
 */
void
nak(int error)
{
  struct tftphdr *tp;
  int length;
  struct errmsg *pe;
  
  tp = (struct tftphdr *)buf;
  tp->th_opcode = htons((u_short)ERROR);
  tp->th_code = htons((u_short)error);
  for (pe = errmsgs; pe->e_code >= 0; pe++)
    if (pe->e_code == error)
      break;
  if (pe->e_code < 0) {
    pe->e_msg = strerror(error - 100);
    tp->th_code = EUNDEF;   /* set 'undef' errorcode */
  }
  strcpy(tp->th_msg, pe->e_msg);
  length = strlen(pe->e_msg);
  tp->th_msg[length] = '\0';
  length += 5;
  
  if ( verbosity >= 2 ) {
    syslog(LOG_INFO, "sending NAK (%d, %s) to %s",
	   error, tp->th_msg, inet_ntoa(from.sin_addr));
  }
  
  if (send(peer, buf, length, 0) != length)
    syslog(LOG_ERR, "nak: %m");
}
