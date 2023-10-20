#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <map>

extern "C" {

#include "dh_session_datatypes.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_eid.h"
#include "sgx_quote_3.h"
#include "sgx_urts.h"

#include "attestation_msgs.h"
#include "log.h"

}

extern "C" sgx_status_t ecall_session_request(sgx_enclave_id_t enclave_id, uint32_t *ret,
			  pcd_dh_dcap_msg1_t *dh_msg1,
                          uint32_t *session_id);

/* Function Description:
 *  This function responds to initiator enclave's connection request by generating and sending back ECDH message 1
 * Parameter Description:
 *  [input] clientfd: this is client's connection id. After generating ECDH message 1, server would send back response through this connection id.
 * */
extern "C" int pcd_sgx_attestation_generate_and_send_session_msg1_resp(sgx_enclave_id_t enclave_id, pcd_sgx_attestation_msg_dh_1_resp_t *msg1resp) {
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
	uint32_t sessionid;

    if (msg1resp == NULL) {
	return -1;
    }

    // call prover enclave to generate ECDH message 1
    ret = ecall_session_request(enclave_id, &status, &msg1resp->dh_msg1, &sessionid);
    if (ret != SGX_SUCCESS)
    {
        pcd_log_error("ERROR: Prover Untrusted: Failed to do ECALL session_request.\n");
        return -1;
    }
	msg1resp->sessionid = sessionid;
    
    return status;
}

extern "C" sgx_status_t ecall_exchange_report(sgx_enclave_id_t enclave_id, uint32_t *ret,
			  pcd_dh_dcap_msg2_t *dh_msg2,
                          pcd_dh_dcap_msg3_t *dh_msg3,
                          uint32_t session_id);

extern "C" int pcd_sgx_attestation_process_exchange_report(sgx_enclave_id_t enclave_id, pcd_sgx_attestation_msg_dh_2_t *msg2, pcd_sgx_attestation_msg_dh_3_t *msg3)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    
    if (!msg2 || !msg3)
        return -1;

    msg3->sessionid = msg2->sessionid; 

    // call prover enclave to process ECDH message 2 and generate message 3
    ret = ecall_exchange_report(enclave_id, &status, &msg2->dh_msg2, &msg3->dh_msg3, msg2->sessionid);
    if (ret != SGX_SUCCESS)
    {
        pcd_log_error("ERROR: Prover Untrusted: exchange_report failure.\n");
        return -1;
    }
	if (status != 0) {
		pcd_log_error("ERROR: Prover Untrusted: exchange_report returned %d\n", status);
		return -1;
	}

    return 0;
}


extern "C" sgx_status_t ecall_generate_response(sgx_enclave_id_t enclave_id, uint32_t *ret,
				     secure_message_t* req_message,
                                     size_t req_message_size,
                                     size_t max_payload_size,
                                     secure_message_t* resp_message,
                                     size_t resp_message_size,
                		     uint32_t session_id);

extern "C" int pcd_sgx_attestation_process_msg_transfer(sgx_enclave_id_t enclave_id, pcd_sgx_attestation_msg_req_t *req_msg, secure_message_t *resp_message)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    size_t resp_message_size;

    if (!req_msg || !resp_message)
    {
        pcd_log_error("ERROR: Prover Untrusted: invalid parameter.\n");
        return -1;
    }

    resp_message_size = sizeof(secure_message_t) + req_msg->max_payload_size;
    memset(resp_message, 0, resp_message_size);
    ret = ecall_generate_response(enclave_id, &status, (secure_message_t *)req_msg->buf, req_msg->size, req_msg->max_payload_size, resp_message, resp_message_size, req_msg->session_id);
    if (ret != SGX_SUCCESS)
    {
        pcd_log_error("ERROR: Prover Untrusted: Enclave generate_response error.\n");
        free(resp_message);
        return -1;
    }

    return 0;
}

extern "C" sgx_status_t ecall_end_session(sgx_enclave_id_t enclave_id, uint32_t *ret, uint32_t session_id);

/* Function Description: This is process session close request from client
 * Parameter Description:
 *  [input] clientfd: this is client connection id
 *  [input] close_req: this is pointer to client's session close request
 * */
extern "C" int pcd_sgx_attestation_process_close_req(sgx_enclave_id_t enclave_id, pcd_sgx_attestation_msg_session_close_t *close_req)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    
    if (!close_req)
        return -1; 

    // call prover enclave to close this session
    ret = ecall_end_session(enclave_id, &status, close_req->session_id);
    if (ret != SGX_SUCCESS)
        return -1;

    return 0;
}

extern "C" int pcd_sgx_attestation_prover_process_msg(sgx_enclave_id_t enclave_id, pcd_sgx_attestation_msg_t *in_msg, pcd_sgx_attestation_msg_t **out_msg, size_t *out_msg_size) {
	int retval;
	if (in_msg == NULL || out_msg == NULL) {
		pcd_log_error("ERROR: Prover Untrusted: NULL msg\n");
		return -1;
	}

	*out_msg = NULL;

	switch (in_msg->header.type) {
		case PCD_SGX_ATT_DH_REQ_MSG1:
			pcd_log("INFO: Received MSG1 REQ\n");
			*out_msg_size = sizeof(pcd_sgx_attestation_msg_t) + sizeof(pcd_sgx_attestation_msg_dh_1_resp_t);
			*out_msg = (pcd_sgx_attestation_msg_t *)malloc(*out_msg_size);
			if (*out_msg == NULL) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to allocate out_msg\n");
				return -1;
			}
			(*out_msg)->header.type = PCD_SGX_ATT_DH_RESP_MSG1;
			(*out_msg)->header.size = sizeof(pcd_sgx_attestation_msg_dh_1_resp_t);

			retval = pcd_sgx_attestation_generate_and_send_session_msg1_resp(enclave_id, 
						(pcd_sgx_attestation_msg_dh_1_resp_t *)(&(*out_msg)->msgbuf));
			if (retval != 0) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to generate msg1 resp\n");
				return -1;
			}
			return 0;
		case PCD_SGX_ATT_DH_MSG2:
			pcd_log("INFO: Received MSG2\n");
			*out_msg_size = sizeof(pcd_sgx_attestation_msg_t) + sizeof(pcd_sgx_attestation_msg_dh_3_t);
			*out_msg = (pcd_sgx_attestation_msg_t *)malloc(*out_msg_size);
			if (*out_msg == NULL) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to allocate out_msg\n");
				return -1;
			}
			(*out_msg)->header.type = PCD_SGX_ATT_DH_MSG3;
			(*out_msg)->header.size = sizeof(pcd_sgx_attestation_msg_dh_3_t);

			retval = pcd_sgx_attestation_process_exchange_report(enclave_id, 
						(pcd_sgx_attestation_msg_dh_2_t *)in_msg->msgbuf,
						(pcd_sgx_attestation_msg_dh_3_t *)(&(*out_msg)->msgbuf));
			if (retval != 0) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to generate msg3\n");
				return -1;
			}
			return 0;
		case PCD_SGX_ATT_DH_MSG_REQ:
			pcd_log("INFO: Received REQ\n");
			*out_msg_size = sizeof(pcd_sgx_attestation_msg_t) + sizeof(secure_message_t) + ((pcd_sgx_attestation_msg_req_t *)in_msg->msgbuf)->max_payload_size;
			*out_msg = (pcd_sgx_attestation_msg_t *)malloc(*out_msg_size);
			if (*out_msg == NULL) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to allocate out_msg\n");
				return -1;
			}
			(*out_msg)->header.type = PCD_SGX_ATT_DH_MSG_RESP;
			(*out_msg)->header.size = sizeof(secure_message_t) + ((pcd_sgx_attestation_msg_req_t *)in_msg->msgbuf)->max_payload_size;

			retval = pcd_sgx_attestation_process_msg_transfer(enclave_id, 
						(pcd_sgx_attestation_msg_req_t *)in_msg->msgbuf,
						(secure_message_t *)(&(*out_msg)->msgbuf));
			if (retval != 0) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to generate msg resp\n");
				return -1;
			}
			return 0;
		case PCD_SGX_ATT_DH_CLOSE_REQ:
			*out_msg_size = sizeof(pcd_sgx_attestation_msg_t);
			*out_msg = (pcd_sgx_attestation_msg_t *)malloc(*out_msg_size);
			if (*out_msg == NULL) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to allocate out_msg\n");
				return -1;
			}
			(*out_msg)->header.type = PCD_SGX_ATT_DH_CLOSE_RESP;
			(*out_msg)->header.size = 0;

			retval = pcd_sgx_attestation_process_close_req(enclave_id,
						(pcd_sgx_attestation_msg_session_close_t *)in_msg->msgbuf);
			if (retval != 0) {
				pcd_log_error("ERROR: Prover Untrusted: Failed to process close request\n");
				return -1;
			}
			return 0;
		default:
			pcd_log_error("ERROR: Prover Untrusted: Unknown msg type %d\n", in_msg->header.type);
			return -1;
	}
	return -1;
}
