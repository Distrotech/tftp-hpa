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
 * remap.c
 *
 * Perform regular-expression based filename remapping.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>

#include "tftpsubs.h"
#include "remap.h"

#define DEADMAN_MAX_STEPS	1024    /* Timeout after this many steps */
#define LINE_MAX 		65536   /* Truncate a line at this many bytes */

#define RULE_REWRITE	0x01	/* This is a rewrite rule */
#define RULE_GLOBAL	0x02	/* Global rule (repeat until no match) */
#define RULE_EXIT	0x04	/* Exit after matching this rule */
#define RULE_RESTART	0x08	/* Restart at the top after matching this rule */
#define RULE_ABORT	0x10	/* Terminate processing with an error */
#define RULE_GETONLY	0x20	/* Applicable to GET only */
#define RULE_PUTONLY	0x40	/* Applicable to PUT only */

struct rule {
  struct rule *next;
  int nrule;
  int rule_flags;
  regex_t rx;
  char *pattern;
};

/* Do \-substitution.  Call with string == NULL to get length only. */
static int genmatchstring(char *string, const char *pattern, const char *input, const regmatch_t *pmatch)
{
  int len = 0;
  int n, mlen;
  int endbytes;

  /* Get section before match; note pmatch[0] is the whole match */
  endbytes = strlen(input) - pmatch[0].rm_eo;
  len = pmatch[0].rm_so + endbytes;
  if ( string ) {
    memcpy(string, input, pmatch[0].rm_so);
    string += pmatch[0].rm_so;
  }

  /* Transform matched section */
  while ( *pattern ) {
    if ( *pattern == '\\' && pattern[1] != '\0' ) {
      if ( pattern[1] < '0' || pattern[1] > '9' ) {
	len++;
	if ( string )
	  *string++ = pattern[1];
      } else {
	n = pattern[1] - '0';
	
	if ( pmatch[n].rm_so != -1 ) {
	  mlen = pmatch[n].rm_eo - pmatch[n].rm_so;
	  len += mlen;
	  if ( string ) {
	    memcpy(string, input+pmatch[n].rm_so, mlen);
	    string += mlen;
	  }
	}
      }
      pattern += 2;
    } else {
      len++;
      if ( string )
	*string++ = *pattern;
      pattern++;
    }
  }

  /* Copy section after match */
  if ( string ) {
    memcpy(string, input+pmatch[0].rm_eo, endbytes);
    string[endbytes] = '\0';
  }

  return len;
}

/* Extract a string terminated by non-escaped whitespace; ignore leading whitespace */
/* Consider an unescaped # to be a comment marker, functionally \n */
static int readescstring(char *buf, char **str)
{
  char *p = *str;
  int wasbs = 0, len = 0;

  while ( *p && isspace(*p) )
    p++;

  if ( ! *p ) {
    *buf = '\0';
    *str = p;
    return 0;
  }

  while ( *p ) {
    if ( !wasbs && (isspace(*p) || *p == '#') ) {
      *buf = '\0';
      *str = p;
      return len;
    }
    /* Important: two backslashes leave us in the !wasbs state! */
    wasbs = !wasbs && ( *p == '\\' );
    *buf++ = *p++;
    len++;
  }

  *buf = '\0';
  *str = p;
  return len;
}

/* Parse a line into a set of instructions */
static int parseline(char *line, struct rule *r)
{
  char buffer[LINE_MAX];
  char *p;
  int rv;
  int rxflags = REG_EXTENDED;
  static int nrule;

  memset(r, 0, sizeof r);
  r->nrule = nrule;

  if ( !readescstring(buffer, &line) )
    return 0;			/* No rule found */

  for ( p = buffer ; *p ; p++ ) {
    switch(*p) {
    case 'r':
      r->rule_flags |= RULE_REWRITE;
      break;
    case 'g':
      r->rule_flags |= RULE_GLOBAL;
      break;
    case 'e':
      r->rule_flags |= RULE_EXIT;
      break;
    case 's':
      r->rule_flags |= RULE_RESTART;
      break;
    case 'a':
      r->rule_flags |= RULE_ABORT;
      break;
    case 'i':
      rxflags |= REG_ICASE;
      break;
    case 'G':
      r->rule_flags |= RULE_GETONLY;
      break;
    case 'P':
      r->rule_flags |= RULE_PUTONLY;
      break;
    default:
      /* boo hoo */
      break;
    }
  }

  /* RULE_GLOBAL only applies when RULE_REWRITE specified */
  if ( !(r->rule_flags & RULE_REWRITE) )
    r->rule_flags &= ~RULE_GLOBAL;

  /* Read and compile the regex */
  if ( !readescstring(buffer, &line) ) {
    /* boo hoo */
    return 0;			/* No rule found */
  }

  if ( (rv = regcomp(&r->rx, buffer, rxflags)) != 0 ) {
    /* boo hoo */
    return 0;			/* No rule found */
  }

  /* Read the rewrite pattern, if any */
  if ( readescstring(buffer, &line) ) {
    r->pattern = xstrdup(buffer);
  } else {
    r->pattern = "";
  }

  nrule++;
  return 1;			/* Rule found */
}

/* Read a rule file */
struct rule *parserulefile(FILE *f)
{
  char line[LINE_MAX];
  struct rule *first_rule = NULL;
  struct rule **last_rule = &first_rule;
  struct rule *this_rule  = xmalloc(sizeof(struct rule));

  while ( fgets(line, LINE_MAX, f) ) {
    if ( parseline(line, this_rule) ) {
      *last_rule = this_rule;
      last_rule = &this_rule->next;
      this_rule = xmalloc(sizeof(struct rule));
    }
  }

  free(this_rule);		/* Last one is always unused */

  return first_rule;
}

/* Execute a rule set on a string; returns a malloc'd new string. */
char *rewrite_string(const char *input, const struct rule *rules, int is_put)
{
  char *current = xstrdup(input);
  char *newstr;
  const struct rule *ruleptr = rules;
  regmatch_t pmatch[10];
  int len;
  int was_match = 0;
  int deadman = DEADMAN_MAX_STEPS;

  for ( ruleptr = rules ; ruleptr ; ruleptr = ruleptr->next ) {
    if ( ((ruleptr->rule_flags & RULE_GETONLY) && is_put) ||
	 ((ruleptr->rule_flags & RULE_PUTONLY) && !is_put) ) {
      continue;			/* Rule not applicable, try next */
    }

    if ( ! deadman-- ) {
      free(current);
      return NULL;		/* Did not terminate! */
    }

    do {
      if ( regexec(&ruleptr->rx, current, 10, pmatch, 0) == 0 ) {
	/* Match on this rule */
	was_match = 1;
	
	if ( ruleptr->rule_flags & RULE_ABORT ) {
	  free(current);
	  return(NULL);
	}
	
	if ( ruleptr->rule_flags & RULE_REWRITE ) {
	  len = genmatchstring(NULL, ruleptr->pattern, current, pmatch);
	  newstr = xmalloc(len+1);
	  genmatchstring(newstr, ruleptr->pattern, current, pmatch);
	  free(current);
	  current = newstr;
	}
      } else {
	break;			/* No match, terminate unconditionally */
      }
      /* If the rule is global, keep going until no match */
    } while ( ruleptr->rule_flags & RULE_GLOBAL );
    
    if ( was_match ) {
      was_match = 0;

      if ( ruleptr->rule_flags & RULE_EXIT ) {
	break;			/* Exit here, we're done */
      } else if ( ruleptr->rule_flags & RULE_RESTART ) {
	ruleptr = rules;	/* Start from the top */
      }
    }
  }

  return current;
}
