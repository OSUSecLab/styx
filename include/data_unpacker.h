#ifndef _PCD_DATA_UNPACKER_H_
#define _PCD_DATA_UNPACKER_H_

#include <stdint.h>

#include "data.h"
#include "tag.h"

#include "policy/policy.h"
#include "crypto/crypto.h"

int pcd_data_unpacker_extract_data(pcd_enc_data_t *input_data,
				void **output_data, size_t *data_size,
				pcd_policy_t **output_policy, 
				pcd_tag_t **output_tags, uint32_t *tag_count,
				pcd_identity_t *owner_id, void *key);

#endif
