#ifndef _PCD_PRODUCER_H_
#define _PCD_PRODUCER_H_

#include "data.h"
#include "tag.h"

#include "policy/policy.h"
#include "crypto/crypto.h"

int pcd_producer_init(pcd_identity_t *owner_id, pcd_policy_t *policy, pcd_delegator_addr_t *delegator_addr,
			 void *key, pcd_crypto_algo_t crypto_algo);
int pcd_producer_generate_data(void *data, size_t data_size, pcd_tag_t *tags, uint32_t tag_count, pcd_enc_data_t **output_data);

#endif