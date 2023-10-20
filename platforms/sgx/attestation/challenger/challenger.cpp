/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "attestation/attestation_errors.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "dh_session_protocol.h"

#include "sgx_tcrypto.h"

#include "dcap_dh_def.h"
#include "dcap_dh.h"
#include "dh_internal.h"
#include "attestation_sessions.h"

#ifdef __cplusplus
extern "C"
{
#endif
    #include "log.h"

    uint32_t (*verify_peer_enclave_trust)(sgx_dh_session_enclave_identity_t *peer_enclave_identity, int challenger_session_id) = NULL;
	
	sgx_status_t ocall_session_request(ATTESTATION_STATUS *ret, pcd_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id, const char *target_path);
	sgx_status_t ocall_exchange_report(ATTESTATION_STATUS *ret, pcd_dh_dcap_msg2_t *dh_msg2, pcd_dh_dcap_msg3_t *dh_msg3, uint32_t session_id, const char *target_path);
	sgx_status_t ocall_send_request(ATTESTATION_STATUS *ret, uint32_t session_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, const char *target_path);
	sgx_status_t ocall_end_session(ATTESTATION_STATUS *ret, uint32_t session_id, const char *target_path);
#ifdef __cplusplus
}
#endif

extern "C" void set_enclave_trust_verifier(uint32_t (*ptr)(sgx_dh_session_enclave_identity_t *peer_enclave_identity, int challenger_session_id)) {
    verify_peer_enclave_trust = ptr;
}


// Create a session with the destination enclave
extern "C" ATTESTATION_STATUS create_session(uint32_t *challenger_session_id, const char *target_path)
{
    dh_session_t *session_info = NULL;
    pcd_dh_dcap_msg1_t dh_msg1; // Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;    // Session Key
    pcd_dh_dcap_msg2_t dh_msg2; // Diffie-Hellman Message 2
    pcd_dh_dcap_msg3_t dh_msg3; // Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    //get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(challenger_session_id)) != SUCCESS) {
	// No more sessions available
        return status;
    }

    session_info =(dh_session_t *)malloc(sizeof(dh_session_t));

    if (!session_info)
    {
	    release_session_id(*challenger_session_id);
        return MALLOC_ERROR;
    }

    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(pcd_dh_dcap_msg1_t));
    memset(&dh_msg2, 0, sizeof(pcd_dh_dcap_msg2_t));
    memset(&dh_msg3, 0, sizeof(pcd_dh_dcap_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    // Intialize the session as a session initiator
    status = pcd_dh_dcap_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return status;
    }

    // Ocall to request for a session with the destination enclave and obtain session id and Message 1 if successful
    status = ocall_session_request(&retstatus, &dh_msg1, &session_id, target_path);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
        	pcd_log_error("ERROR: ocall_session_request returned %d\n", retstatus);
		SAFE_FREE(session_info);
		release_session_id(*challenger_session_id);
		return ((ATTESTATION_STATUS)retstatus);
	}
    }
    else
    {
		pcd_log_error("ERROR: ocall_session_request failed with %d\n", status);
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return ATTESTATION_SE_ERROR;
    }
    // Process the message 1 obtained from desination enclave and generate message 2
    status = pcd_dh_dcap_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
	pcd_log_error("ERROR: pcd_dh_dcap_initiator_proc_msg1 returned %d\n", status); 
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return status;
    }

    // Send Message 2 to Destination Enclave and get Message 3 in return
    status = ocall_exchange_report(&retstatus, &dh_msg2, &dh_msg3, session_id, target_path);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
			pcd_log_error("ERROR: ocall_exchange_report returned %d\n", retstatus);
	    SAFE_FREE(session_info);
	    release_session_id(*challenger_session_id);
            return ((ATTESTATION_STATUS)retstatus);
	}
    }
    else
    {
		pcd_log_error("ERROR: ocall_exchange_report failed with %d\n", status);
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return ATTESTATION_SE_ERROR;
    }

    // Process Message 3 obtained from the destination enclave
    status = pcd_dh_dcap_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if (SGX_SUCCESS != status)
    {
		pcd_log_error("ERROR: proc_msg3 failed with %d\n", status); 
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return status;
    }

    // Verify the identity of the destination enclave
    if (verify_peer_enclave_trust == NULL) {
		pcd_log_error("ERROR: verify_peer_trust not initialised\n");
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return ATTESTATION_ERROR;
    }
    if ((*verify_peer_enclave_trust)(&responder_identity, *challenger_session_id) != SUCCESS)
    {
		pcd_log_error("ERROR: Wrong enclave\n");
	SAFE_FREE(session_info);
	release_session_id(*challenger_session_id);
        return INVALID_SESSION;
    }

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->challenger_session_id = *challenger_session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));

    // Add to session map
    retstatus = insert_session_info(*challenger_session_id, *session_info);
    if (retstatus != SUCCESS) {
	SAFE_FREE(session_info);
        release_session_id(*challenger_session_id);
	return retstatus;
    }
    SAFE_FREE(session_info);

    return retstatus;
}



// Request for the response size, send the request message to the destination enclave and receive the response message back
extern "C" ATTESTATION_STATUS challenger_send_request_receive_response(uint8_t *inp_buff,
                                                 size_t inp_buff_len,
                                                 size_t max_out_buff_size,
                                                 uint8_t *out_buff,
                                                 size_t *out_buff_len,
                                                 int challenger_session_id, 
                                                 const char *target_path)
{
    dh_session_t *session_info;
    const uint8_t *plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    uint32_t retstatus;
    secure_message_t *req_message;
    secure_message_t *resp_message;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t max_resp_message_length;
    plaintext = (const uint8_t *)(" ");
    plaintext_length = 0;

    session_info = get_session_info(challenger_session_id);
    if (session_info == NULL) {
        pcd_log_error("ERROR: Challenger: Cannot find session\n");
        return INVALID_SESSION;
    }

    if (!inp_buff)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // Just provisioning some keys. In demo it shoule never reach overflowing point
    // TODO: Make it unlimited
    if (session_info->active.counter == ((uint32_t)-2))
    {
        pcd_log_error("ERROR: Challenger: Unexpected exhausted counter!\n");
        return INVALID_SESSION;
    }

    // Allocate memory for the AES-GCM request message
    req_message = (secure_message_t *)malloc(sizeof(secure_message_t) + inp_buff_len);
    if (!req_message)
        return MALLOC_ERROR;
    memset(req_message, 0, sizeof(secure_message_t) + inp_buff_len);

    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;

    // Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    // Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    // Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    // Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t *)inp_buff, data2encrypt_length,
                                        reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                                        reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                                        sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                                        &(req_message->message_aes_gcm_data.payload_tag));

    if (SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return status;
    }

    // Allocate memory for the response message
    resp_message = (secure_message_t *)malloc(sizeof(secure_message_t) + max_out_buff_size);
    if (!resp_message)
    {
        SAFE_FREE(req_message);
        return MALLOC_ERROR;
    }

    memset(resp_message, 0, sizeof(secure_message_t) + max_out_buff_size);

    // Ocall to send the request to the Destination Enclave and get the response message back
    status = ocall_send_request(&retstatus, session_info->session_id, req_message,
                                (sizeof(secure_message_t) + inp_buff_len), max_out_buff_size,
                                resp_message, (sizeof(secure_message_t) + max_out_buff_size), target_path);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
        {
            SAFE_FREE(req_message);
            SAFE_FREE(resp_message);
            return ((ATTESTATION_STATUS)retstatus);
        }
    }
    else
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return ATTESTATION_SE_ERROR;
    }

    max_resp_message_length = sizeof(secure_message_t) + max_out_buff_size;

    if (sizeof(resp_message) > max_resp_message_length)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return INVALID_PARAMETER_ERROR;
    }

    // Code to process the response message from the Destination Enclave

    decrypted_data_length = resp_message->message_aes_gcm_data.payload_size;
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t *)malloc(decrypted_data_length);
    if (!decrypted_data)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return MALLOC_ERROR;
    }
    memset(&l_tag, 0, 16);

    memset(decrypted_data, 0, decrypted_data_length);

    // Decrypt the response message payload
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, resp_message->message_aes_gcm_data.payload,
                                        decrypted_data_length, decrypted_data,
                                        reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                                        sizeof(resp_message->message_aes_gcm_data.reserved), &(resp_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                                        &resp_message->message_aes_gcm_data.payload_tag);

    if (SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(resp_message);
        return status;
    }

    // Verify if the nonce obtained in the response is equal to the session nonce + 1 (Prevents replay attacks)
    if (*((uint32_t *)resp_message->message_aes_gcm_data.reserved) != (session_info->active.counter + 1))
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        SAFE_FREE(decrypted_data);
        return INVALID_PARAMETER_ERROR;
    }

    // Update the value of the session nonce in the source enclave
    session_info->active.counter = session_info->active.counter + 1;

    memcpy(out_buff_len, &decrypted_data_length, sizeof(decrypted_data_length));
    memcpy(out_buff, decrypted_data, decrypted_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(req_message);
    SAFE_FREE(resp_message);
    return SUCCESS;
}

// Close a current session
extern "C" ATTESTATION_STATUS close_session(int challenger_session_id, const char *target_path)
{
    dh_session_t *session_info;
    sgx_status_t status;
    uint32_t retstatus;

    // Get the session info
    session_info = get_session_info(challenger_session_id);
    if (session_info == NULL) {
        pcd_log_error("ERROR: Challenger: Cannot find session\n");
        return INVALID_SESSION;
    }

    // Ocall to ask the destination enclave to end the session
    status = ocall_end_session(&retstatus, session_info->session_id, target_path);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }

    erase_session(challenger_session_id);

    release_session_id(challenger_session_id);

    return SUCCESS;
}
