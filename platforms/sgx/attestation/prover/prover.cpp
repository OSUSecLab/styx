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

#include <stdio.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "attestation/attestation_errors.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "dh_session_protocol.h"

#include "sgx_tcrypto.h"
#include "dcap_dh_def.h"
#include "dcap_dh.h"
#include "dh_session_datatypes.h"

#include "attestation_sessions.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "log.h"

#ifdef __cplusplus
}
#endif

//Create a session with the destination enclave

//Handle the request from Source Enclave for a session
extern "C" ATTESTATION_STATUS ecall_session_request(pcd_dh_dcap_msg1_t *dh_msg1,
                          uint32_t *session_id )
{
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;
	int retstatus;

    if(!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Intialize the session as a session responder
    status = pcd_dh_dcap_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    //get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS) {
	// No more sessions available
        return status;
    }

    session_info.status = IN_PROGRESS;

    //Generate Message1 that will be returned to Source Enclave
    status = pcd_dh_dcap_responder_gen_msg1((pcd_dh_dcap_msg1_t*)dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        release_session_id(*session_id);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));

    // Store the session information under the corresponding source enclave id key
    retstatus = insert_session_info(*session_id, session_info);
    if (retstatus != SUCCESS) {
        release_session_id(*session_id);
	return retstatus;
    }

    return retstatus;
}

extern "C" ATTESTATION_STATUS ecall_end_session(uint32_t session_id);

//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
extern "C" ATTESTATION_STATUS ecall_exchange_report(pcd_dh_dcap_msg2_t *dh_msg2,
                          pcd_dh_dcap_msg3_t *dh_msg3,
                          uint32_t session_id)
{

    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;

    if(!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    do
    {
        //Retrieve the session information for the corresponding source enclave id
        session_info = get_session_info(session_id);
    	if (session_info == NULL) {
		pcd_log_error("ERROR: Prover: Cannot find session\n");
		status = INVALID_SESSION;
		break;
    	}

        if(session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        //Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = pcd_dh_dcap_responder_proc_msg2(dh_msg2,
                                                       dh_msg3,
                                                       &sgx_dh_session,
                                                       &dh_aek);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        //save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    } while(0);

    if(status != SUCCESS)
    {
        ecall_end_session(session_id);
    }

    return status;
}

extern "C" uint32_t message_exchange_response_generator(uint8_t* decrypted_data,
                                              uint32_t decrypted_data_length,
                                              uint8_t** resp_buffer,
                                              size_t* resp_length);

//Process the request from the Source enclave and send the response message back to the Source enclave
extern "C" ATTESTATION_STATUS ecall_generate_response(secure_message_t* req_message,
                                     size_t req_message_size,
                                     size_t max_payload_size,
                                     secure_message_t* resp_message,
                                     size_t resp_message_size,
                		     uint32_t session_id)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    size_t resp_data_length;
    size_t resp_message_calc_size;
    uint8_t* resp_data;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    secure_message_t* temp_resp_message;
    uint32_t ret;
    sgx_status_t status;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;
	
	//pcd_log("INFO: entering generate_response\n");

    if(!req_message || !resp_message)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // Get the session information from the map corresponding to the source enclave id
    session_info = get_session_info(session_id);
    if (session_info == NULL) {
	    pcd_log_error("ERROR: Prover: Cannot find session\n");
	    return INVALID_SESSION;
    }

    if(session_info->status != ACTIVE)
    {
        pcd_log_error("Prover: Session inactive\n");
        return INVALID_SESSION;
    }

    //Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;

    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;

    //Verify the size of the payload
    if(expected_payload_size != decrypted_data_length)
        return INVALID_PARAMETER_ERROR;

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
        pcd_log_error("Prover: Failed to allocate decrypted data\n");
        return MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the request message payload from source enclave
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload,
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                &req_message->message_aes_gcm_data.payload_tag);

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        pcd_log_error("Prover: Failed to decrypt message payload\n");
        return status;
    }
	
	//pcd_log("INFO: Successfully decrypted message payload\n");

    // Verify if the nonce obtained in the request is equal to the session nonce
    if(*((uint32_t*)req_message->message_aes_gcm_data.reserved) != session_info->active.counter || *((uint32_t*)req_message->message_aes_gcm_data.reserved) > ((uint32_t)-2))
    {
        SAFE_FREE(decrypted_data);
        pcd_log_error("Prover: Wrong nonce\n");
        return INVALID_PARAMETER_ERROR;
    }


    //Call the generic secret response generator for message exchange
    ret = message_exchange_response_generator(decrypted_data, decrypted_data_length, &resp_data, &resp_data_length);
    if(ret != 0)
    {
        SAFE_FREE(decrypted_data);
        return INVALID_SESSION;
    }

	//pcd_log("INFO: Successfully generated response\n");

    if(resp_data_length > max_payload_size)
    {
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t)+ resp_data_length;

    if(resp_message_calc_size > resp_message_size)
    {
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    //Code to build the response back to the Source Enclave
    temp_resp_message = (secure_message_t*)malloc(resp_message_calc_size);
    if(!temp_resp_message)
    {
            SAFE_FREE(decrypted_data);
            return MALLOC_ERROR;
    }

    memset(temp_resp_message,0,sizeof(secure_message_t)+ resp_data_length);
    const uint32_t data2encrypt_length = (uint32_t)resp_data_length;
    temp_resp_message->session_id = session_info->session_id;
    temp_resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Increment the Session Nonce (Replay Protection)
    session_info->active.counter = session_info->active.counter + 1;

    //Set the response nonce as the session nonce
    memcpy(&temp_resp_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    //Prepare the response message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)resp_data, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.reserved)),
                sizeof(temp_resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(temp_resp_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        SAFE_FREE(temp_resp_message);
        return status;
    }

    SAFE_FREE(resp_data);

    memset(resp_message, 0, sizeof(secure_message_t)+ resp_data_length);
    memcpy(resp_message, temp_resp_message, sizeof(secure_message_t)+ resp_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(temp_resp_message);

    return SUCCESS;
}


//Respond to the request from the Source Enclave to close the session
extern "C" ATTESTATION_STATUS ecall_end_session(uint32_t session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    //Get the session information from the map corresponding to the source enclave id
    erase_session(session_id);

    //Update the session id tracker
    release_session_id(session_id);

    return status;

}
