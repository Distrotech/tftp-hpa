/*
 * bsdsignal.c
 *
 * Use sigaction() to simulate BSD signal()
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>

void bsd_signal(int signum, void (*handler)(int))
{
  struct sigaction action;

  memset(&action, 0, sizeof action);
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;
  
  sigaction(hander, action, NULL);
}
