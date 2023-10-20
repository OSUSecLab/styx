#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "error_codes.h"
#include "log.h"
#include "data_packer.h"
#include "data.h"
#include "tag.h"

#include "crypto/crypto.h"
#include "policy/policy.h"

static void *pcd_producer_key;
static pcd_identity_t pcd_producer_owner_id;
static pcd_policy_t *pcd_producer_policy;
static pcd_delegator_addr_t pcd_producer_delegator_addr;
static pcd_crypto_algo_t pcd_producer_crypto_algo;

int pcd_producer_init(pcd_identity_t *owner_id, pcd_policy_t *policy, pcd_delegator_addr_t *delegator_addr,
			 void *key, pcd_crypto_algo_t crypto_algo) {
	if (owner_id == NULL || policy == NULL || delegator_addr == NULL || key == NULL) {
		return PCD_NULL_ARG;
	}

	if (crypto_algo < 0 || crypto_algo > PCD_CRYPTO_ALGO_MAX_INDEX) {
		return PCD_OUT_OF_RANGE;
	}
	
	pcd_producer_crypto_algo = crypto_algo;
	memcpy(&pcd_producer_owner_id, owner_id, sizeof(pcd_identity_t));
	memcpy(&pcd_producer_delegator_addr, delegator_addr, sizeof(pcd_delegator_addr_t));
	pcd_producer_policy = policy;
	pcd_producer_key = key;

	return PCD_OK;
}


int pcd_producer_generate_data(void *data, size_t data_size, pcd_tag_t *tags, uint32_t tag_count, pcd_enc_data_t **output_data) {
	int status;
	
	if (data == NULL || tags == NULL || tag_count == 0 || output_data == NULL) {
		return PCD_NULL_ARG;
	}

	status = pcd_data_packer_generate_data(data, data_size, &pcd_producer_owner_id,
				&pcd_producer_delegator_addr, pcd_producer_policy,
				tags, tag_count, pcd_producer_crypto_algo, pcd_producer_key,
				output_data);
	if (status != PCD_OK) {
		pcd_log_error("ERROR: pcd_producer_generate_data: Packer failed to generate data with %d\n", status);
		return status;
	}

	return status;
}
