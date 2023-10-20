#ifndef _PCD_SGX_SECRET_OWNER_H_
#define _PCD_SGX_SECRET_OWNER_H_

#include "identity.h"
#include "secret.h"

int pcd_register_secret_to_remote(pcd_identity_t *data_owner_identity, const char *delegator_address, pcd_secret_t *input_secret);

#endif