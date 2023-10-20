#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "error_codes.h"
#include "log.h"
#include "data_packer.h"
#include "data_unpacker.h"
#include "data.h"
#include "tag.h"
#include "secret.h"

#include "crypto/crypto.h"
#include "policy/policy.h"

int pcd_transformer_release(pcd_identity_t *data_owner_id) {
	pcd_secret_release(data_owner_id);
	return PCD_OK;
}

int pcd_transformer_repack_data(void *data, size_t data_size,
				pcd_identity_t *data_owner_id,
				pcd_delegator_addr_t *delegator_addr,
				pcd_policy_t *policy,
				pcd_tag_t *tags, uint32_t tag_count,
				pcd_crypto_algo_t crypto_algo,
				pcd_enc_data_t **output_data) {
	int status;
	pcd_secret_t *secret;
	
	if (data == NULL || data_owner_id == NULL ||  delegator_addr == NULL
		|| policy == NULL || tags == NULL || tag_count == 0 || output_data == NULL) {
		return PCD_NULL_ARG;
	}

	// Get key from secret storage
	status = pcd_secret_retrieve(data_owner_id, &secret);
	if(status != PCD_OK) {
		return status;
	}

	status = pcd_data_packer_generate_data(data, data_size, data_owner_id,
				delegator_addr, policy,
				tags, tag_count, crypto_algo, (void *)(&secret->secret),
				output_data);
	if (status != PCD_OK) {
		pcd_secret_release(data_owner_id);
		pcd_log_error("ERROR: pcd_producer_generate_data: Packer failed to generate data with %d\n", status);
		return status;
	}
	pcd_secret_release(data_owner_id);

	return status;
}

int pcd_transformer_extract_data(pcd_enc_data_t *input_data, 
				void **output_data, size_t *data_size,
				pcd_policy_t **policy, pcd_tag_t **tags,
				uint32_t *tag_count, pcd_identity_t *data_owner_id,
				pcd_crypto_algo_t *crypto_algo, 
				pcd_delegator_addr_t *delegator_addr) {
	int status;
	pcd_secret_t *secret;
	
	if (input_data == NULL || output_data == NULL || data_size == NULL) {
		return PCD_NULL_ARG;
	}
    memcpy(delegator_addr, &input_data->delegator_addr, sizeof(pcd_delegator_addr_t));

	// Fetch secret
	status = pcd_secret_fetch(&input_data->owner_id, delegator_addr, &secret);
	if (status != PCD_OK) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Failed to fetch secret with %d\n", status);
		return status;
	}

	status = pcd_data_unpacker_extract_data(input_data,
				output_data, data_size,
				policy, tags, tag_count,
				data_owner_id, (void *)(&secret->secret));
	if (status != PCD_OK) {
		pcd_log_error("ERROR: pcd_transformer_extract_data: Unpacker failed to extract data with %d\n", status);
		return status;
	}
	*crypto_algo = input_data->enc_algo;	
	return PCD_OK;
}
