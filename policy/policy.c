#include <string.h>

#include "error_codes.h"
#include "policy/policy.h"

static pcd_policy_type_struct_t *pcd_policy_types[PCD_POLICY_TYPE_MAX_INDEX + 1];

pcd_policy_type_struct_t *pcd_policy_get(pcd_policy_type_t type_id) {
	if (type_id < 0 || type_id > PCD_POLICY_TYPE_MAX_INDEX) {
		return NULL;
	}

	return pcd_policy_types[type_id];
}

int pcd_policy_type_register(pcd_policy_type_struct_t *policy_type, pcd_policy_type_t type_id) {
	if (policy_type == NULL) {
		return PCD_NULL_ARG;
	}

	if (type_id < 0 || type_id > PCD_POLICY_TYPE_MAX_INDEX) {
		return PCD_OUT_OF_RANGE;
	}

	if (pcd_policy_types[type_id] != NULL) {
		return PCD_REINIT;
	}

	pcd_policy_types[type_id] = policy_type;

	return PCD_OK;
}

#include "policy/simple.h"

int pcd_policy_init() {
	memset(&pcd_policy_types, 0, sizeof(pcd_policy_types));

#ifdef PCD_CONFIG_POLICY_SIMPLE
	pcd_policy_simple_init();
#endif

	return PCD_OK;
}
