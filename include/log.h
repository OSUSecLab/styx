#include <stdio.h>
#include <string.h>

#ifndef _PCD_LOG_H_
#define _PCD_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

void pcd_log_error(const char *fmt, ...);
void pcd_log_warning(const char *fmt, ...);
void pcd_log(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif