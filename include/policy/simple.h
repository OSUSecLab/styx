#ifndef _PCD_SIMPLE_H_
#define _PCD_SIMPLE_H_

#ifdef PCD_CONFIG_POLICY_SIMPLE

#include <stdint.h>

#include "tag.h"

typedef uint8_t pcd_policy_simple_cred_t;

#define PCD_POLICY_SIMPLE_USER	0
#define PCD_POLICY_SIMPLE_ADMIN	1

typedef struct {
	pcd_tag_t tag;
	pcd_policy_simple_cred_t cred;
} pcd_policy_simple_rule_t;

typedef struct {
	uint64_t rule_count;
	pcd_policy_simple_rule_t rules[];
} pcd_policy_simple_policy_t;

int pcd_policy_simple_init(void);
int pcd_policy_simple_exit(void);

#endif // PCD_CONFIG_POLICY_SIMPLE

#endif