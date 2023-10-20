extern "C" {

#include "error_codes.h"
#include "identity.h"
#include "log.h"
#include "secret.h"

#include "attestation/attestation_errors.h"
#include "attestation/sgx_challenger.h"

}

extern "C" int pcd_request_secret(pcd_identity_t *data_owner_identity, const char *delegator_address, pcd_secret_t **output_secret) {
	ATTESTATION_STATUS ret_status;
	uint32_t challenger_session_id;
	size_t max_buffer_size;
	size_t output_buf_size;
	pcd_secret_req_t *secret_req;
	pcd_secret_t *received_secret;

	*output_secret = NULL;

	ret_status = create_session(&challenger_session_id, delegator_address);
	if (ret_status != SUCCESS) {
		pcd_log_error("ERROR: pcd_request_secret: create_session returned %d\n", ret_status);
		return -1;
	}

	max_buffer_size = 1024 + sizeof(pcd_secret_req_t);
	secret_req = (pcd_secret_req_t *)malloc(max_buffer_size);
	if (secret_req == NULL) {
		pcd_log_error("ERROR: pcd_request_secret: failed to malloc secret request\n");
		return PCD_REMOTE_FAILED;
	}

	secret_req->req_type = PCD_SECRET_REQ_REQUEST;
	memcpy(&secret_req->id, data_owner_identity, sizeof(pcd_identity_t));

	ret_status = challenger_send_request_receive_response((uint8_t *)secret_req,
                                                 sizeof(pcd_secret_req_t),
                                                 max_buffer_size,
                                                 (uint8_t *)secret_req,
                                                 &output_buf_size,
                                                 challenger_session_id, 
                                                 delegator_address);
	if (ret_status != SUCCESS) {
		pcd_log_error("ERROR: pcd_request_secret: challenger_send_request_receive_response returned %d\n", ret_status);
		free(secret_req);
		return PCD_REMOTE_FAILED;
	}

	if (secret_req->req_type == PCD_SECRET_REQ_RESPONSE_NOT_FOUND) {
		pcd_log_error("ERROR: pcd_request_secret: secret not found on remote delegator");
		free(secret_req);
		return PCD_NOT_FOUND;
	}
	else if (secret_req->req_type == PCD_SECRET_REQ_RESPONSE_DENINED) {
		pcd_log_error("ERROR: pcd_request_secret: secret provisioning denined from remote delegator");
		free(secret_req);
		return PCD_DENINED;
	}
	else if (secret_req->req_type == PCD_SECRET_REQ_RESPONSE_OK) {
		received_secret = (pcd_secret_t *)malloc(sizeof(pcd_secret_t) + secret_req->secret.secret_size);
		if (received_secret == NULL) {
			pcd_log_error("ERROR: pcd_request_secret: failed to malloc received secret\n");
			return PCD_MEMERR;
		}

		memcpy(received_secret, &secret_req->secret, sizeof(pcd_secret_t) + secret_req->secret.secret_size);
	}
	else {
		pcd_log_error("ERROR: pcd_request_secret: unexpected response");
		free(secret_req);
		return PCD_REMOTE_FAILED;
	}
	
	ret_status = close_session(challenger_session_id, delegator_address);
	if (ret_status != SUCCESS) {
		pcd_log_error("ERROR: pcd_request_secret: challenger_send_request_receive_response returned %d\n", ret_status);
		free(secret_req);
		free(received_secret);
		return PCD_REMOTE_FAILED;
	}

	free(secret_req);
	*output_secret = received_secret;

	return PCD_OK;
}
