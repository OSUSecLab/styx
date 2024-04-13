#ifndef _PCD_DEMO_POLICY_DISC_H_
#define _PCD_DEMO_POLICY_DISC_H_

#include <stdint.h>

#include "identity.h"
#include "policy/policy_def.h"
#include "crypto/sha256.h"

#define PCD_DEMO_POLICY_TYPE_PROGRAM_HASH	0x01
#define PCD_DEMO_POLICY_TYPE_ENTRY_CAP		0x02
#define PCD_DEMO_POLICY_TYPE_CUSTODIAN		0x03

static pcd_policy_type_t pcd_demo_policy_type = {
	0x91, 0xda, 0xd8, 0x6e, 0x74, 0x24, 0x11, 0xee, 0xb9, 0x62, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02
};

typedef struct _pcd_demo_policy_rule_t {
	uint8_t rule_type;
	union {
		pcd_sha256_t program_hash;
		uint32_t entry_cap_percentage;
		pcd_identity_t custodian_id;
	};
} __attribute__((packed)) pcd_demo_policy_rule_t;

typedef struct _pcd_demo_attribute_t {
	pcd_identity_t custodian_id;
	uint32_t number_of_entries;
} __attribute__((packed)) pcd_demo_attribute_t;

#endif