/*
 * xstrdup.c
 *
 * Simple error-checking version of strdup()
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *xstrdup(const char *s)
{
  char *p = strdup(s);

  if ( !p ) {
    fprintf(stderr, "Out of memory!\n");
    exit(128);
  }

  return p;
}
