#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "error_codes.h"
#include "log.h"
#include "data_unpacker.h"
#include "data.h"
#include "tag.h"
#include "secret.h"

#include "crypto/crypto.h"
#include "policy/policy.h"

void *pcd_consumer_policy_cred[PCD_POLICY_TYPE_MAX_INDEX + 1] = { [0 ... PCD_POLICY_TYPE_MAX_INDEX] = NULL };

int pcd_consumer_register_credential(void *cred, pcd_policy_type_t policy_type) {
	int status;

	//if (pcd_consumer_policy_cred[policy_type] != NULL) {
	//	// Can report a warning. 
	//	status = PCD_REINIT;
	//}

	pcd_consumer_policy_cred[policy_type] = cred;

	return PCD_OK;
}

int pcd_consumer_extract_data(pcd_enc_data_t *input_data, void **output_data, size_t *data_size) {
	int i;
	int status;
	void *cred;
	void *tmp_output_data;
	size_t tmp_data_size;
	pcd_policy_type_struct_t *policy_struct;
	pcd_policy_t *policy;
	pcd_tag_t *tags;
	uint32_t tag_count;
	pcd_identity_t data_owner_id;
	pcd_secret_t *secret;
	pcd_delegator_addr_t delegator_addr;

	if (input_data == NULL || output_data == NULL || data_size == NULL) {
		return PCD_NULL_ARG;
	}

	memcpy(&delegator_addr, &input_data->delegator_addr, sizeof(pcd_delegator_addr_t));

	// Fetch secret
	status = pcd_secret_fetch(&input_data->owner_id, &delegator_addr, &secret);
	if (status != PCD_OK) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Failed to fetch secret with %d\n", status);
		return status;
	}
	pcd_log("INFO: pcd_data_pcaker_generate_data: fetched secret\n");

	status = pcd_data_unpacker_extract_data(input_data,
				&tmp_output_data, &tmp_data_size,
				&policy, &tags, &tag_count,
				&data_owner_id, (void *)(&secret->secret));
	if (status != PCD_OK) {
		pcd_log_error("ERROR: pcd_consumer_extract_data: Unpacker failed to extract data with %d\n", status);
		return status;
	}

	pcd_secret_release(&input_data->owner_id);

	// Evaluate policy
	policy_struct = pcd_policy_get(policy->type);
	if (policy_struct == NULL) {
		free(tmp_output_data);
		free(policy);
		free(tags);
		return PCD_POLICY_NSUPPORT;
	}

	pcd_log("got policy\n");

	// Note that cred can be NULL if the 'crypto' algorithm does not need a credential
	cred = pcd_consumer_policy_cred[policy->type];
	
	pcd_log("cred got\n");

	for (i = 0; i < tag_count; i++) {
		pcd_log("evaling %d\n", i);
		status = (*policy_struct->eval)(&tags[i], cred, (void *)(&policy->policy_buffer));
		pcd_log("evaled %d\n", i);
		if (status != PCD_OK) {
			pcd_log_error("ERROR: pcd_consumer_extract_data: Policy denined with %d\n", status);
			free(tmp_output_data);
			free(policy);
			free(tags);
			return status;
		}
	}

	*output_data = tmp_output_data;
	*data_size = tmp_data_size;
	free(policy);
	free(tags);
	
	return PCD_OK;
}
