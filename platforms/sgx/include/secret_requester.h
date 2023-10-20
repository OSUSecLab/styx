#ifndef _PCD_SGX_SECRET_REQUESTER_H_
#define _PCD_SGX_SECRET_REQUESTER_H_

#include "identity.h"
#include "secret.h"

int pcd_request_secret(pcd_identity_t *data_owner_identity, const char *delegator_address, pcd_secret_t **output_secret);

#endif