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
 * remap.h
 *
 * Prototypes for regular-expression based filename remapping.
 */

#include <stdlib.h>
#include <stdio.h>
#include "../config.h"

/* Opaque type */
struct rule;

#ifdef WITH_REGEX

/* Read a rule file */
struct rule *parserulefile(FILE *);

/* Execute a rule set on a string; returns a malloc'd new string. */
char *rewrite_string(const char *, const struct rule *, int);

#endif
