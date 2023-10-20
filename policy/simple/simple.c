#include <stdint.h>

#include "error_codes.h"
#include "log.h"
#include "tag.h"


#include "policy/policy.h"
#include "policy/simple.h"

int pcd_policy_simple_compare_cred(void *cred1, void *cred2) {
	return !(*(uint64_t *)cred1 == *(uint64_t *)cred2);
}

int pcd_policy_simple_eval(pcd_tag_t *tag, void *cred, void *policy) {
	pcd_policy_simple_cred_t *simple_cred = (pcd_policy_simple_cred_t *)cred;
	pcd_policy_simple_policy_t *simple_policy = (pcd_policy_simple_policy_t *)policy;
	uint64_t i;
	
	pcd_log("tag = 0x%016llX, cred = 0x%016llX, policy->rule_count = %d\n", tag, cred, simple_policy->rule_count);

	for (i = 0; i < simple_policy->rule_count; i++) {
		if (!pcd_compare_tag(tag, &(simple_policy->rules[i].tag))) {
			if ((uint64_t)*simple_cred == (uint64_t)simple_policy->rules[i].cred) {
				return PCD_OK;
			}
		}
	}

	return PCD_DENINED;
}

pcd_policy_type_struct_t pcd_policy_type_simple = {
	.compare_cred = &pcd_policy_simple_compare_cred,
	.eval = &pcd_policy_simple_eval
};

int pcd_policy_simple_init(void) {
	return pcd_policy_type_register(&pcd_policy_type_simple, PCD_POLICY_SIMPLE);
}

int pcd_policy_simple_exit(void) {
	return PCD_OK;
}
