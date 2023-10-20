#ifndef _SGX_PROVER_H_
#define _SGX_PROVER_H_

#include "attestation/attestation_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

ATTESTATION_STATUS ecall_session_request(pcd_dh_dcap_msg1_t *dh_msg1,
                          uint32_t *session_id);





#ifdef __cplusplus
}
#endif

#endif