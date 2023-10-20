#ifndef _PCD_POLICY_H_
#define _PCD_POLICY_H_

#include <stdint.h>

#include "tag.h"

typedef uint32_t pcd_policy_type_t;
#define PCD_POLICY_SIMPLE		0x0000

#define PCD_POLICY_TYPE_MAX_INDEX	0x0000

typedef struct {
	int (*compare_cred)(void *, void *);
	int (*eval)(pcd_tag_t *tag, void *cred, void *policy);
} pcd_policy_type_struct_t;

typedef struct {
	pcd_policy_type_t type;
	uint64_t policy_size;

	uint8_t policy_buffer[];
} __attribute__((packed)) pcd_policy_t;

pcd_policy_type_struct_t *pcd_policy_get(pcd_policy_type_t type_id);
int pcd_policy_type_register(pcd_policy_type_struct_t *policy_type, pcd_policy_type_t type_id);
int pcd_policy_init(void);

#endif
