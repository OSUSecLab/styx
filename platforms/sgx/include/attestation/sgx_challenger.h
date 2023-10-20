#ifndef _SGX_CHALLENGER_H_
#define _SGX_CHALLENGER_H_

#include "attestation/attestation_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "dcap_dh_def.h"

void set_enclave_trust_verifier(uint32_t (*ptr)(sgx_dh_session_enclave_identity_t *peer_enclave_identity, int challenger_session_id));

ATTESTATION_STATUS create_session(uint32_t *challenger_session_id, const char *target_path);

ATTESTATION_STATUS challenger_send_request_receive_response(uint8_t *inp_buff,
                                                 size_t inp_buff_len,
                                                 size_t max_out_buff_size,
                                                 uint8_t *out_buff,
                                                 size_t *out_buff_len,
                                                 int challenger_session_id, 
                                                 const char *target_path);


ATTESTATION_STATUS close_session(int challenger_session_id, const char *target_path);


#ifdef __cplusplus
}
#endif

#endif
