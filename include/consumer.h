#ifndef _PCD_CONSUMER_H_
#define _PCD_CONSUMER_H_

#include "policy/policy.h"
#include "data.h"

int pcd_consumer_register_credential(void *cred, pcd_policy_type_t policy_type);
int pcd_consumer_extract_data(pcd_enc_data_t *input_data, void **output_data, size_t *data_size);

#endif
