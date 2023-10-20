#ifndef _PCD_PRODUCER_H_
#define _PCD_PRODUCER_H_

#include "data.h"
#include "tag.h"
#include "identity.h"

#include "policy/policy.h"
#include "crypto/crypto.h"

int pcd_transformer_release(pcd_identity_t *data_owner_id);
int pcd_transformer_repack_data(void *data, size_t data_size,
				pcd_identity_t *data_owner_id,
				pcd_delegator_addr_t *delegator_addr,
				pcd_policy_t *policy,
				pcd_tag_t *tags, uint32_t tag_count,
				pcd_crypto_algo_t crypto_algo,
				pcd_enc_data_t **output_data);
int pcd_transformer_extract_data(pcd_enc_data_t *input_data, 
				void **output_data, size_t *data_size,
				pcd_policy_t **policy, pcd_tag_t **tags,
				uint32_t *tag_count, pcd_identity_t *data_owner_id,
				pcd_crypto_algo_t *crypto_algo, 
				pcd_delegator_addr_t *delegator_addr);

#endif
