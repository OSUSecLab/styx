#ifndef _PCD_SGX_PROVER_UNTRUSTED_H_
#define _PCD_SGX_PROVER_UNTRUSTED_H_

#include "attestation_msgs.h"

int pcd_sgx_attestation_prover_process_msg(sgx_enclave_id_t enclave_id, pcd_sgx_attestation_msg_t *in_msg, pcd_sgx_attestation_msg_t **out_msg, size_t *out_msg_size);

#endif
