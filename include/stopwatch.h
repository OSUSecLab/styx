#ifndef _PCD_STOPWATCH_H_
#define _PCD_STOPWATCH_H_

#ifdef PCD_CONFIG_EVAL

#include <stdint.h>

uint64_t pcd_eval_stopwatch_gettime(void);
void pcd_eval_stopwatch_start(uint64_t *watch);
void pcd_eval_stopwatch_lap(char *label, uint64_t *watch, char print);

#endif

#endif