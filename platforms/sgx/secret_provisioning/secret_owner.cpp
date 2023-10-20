#include <cstdlib>

extern "C" {

#include "identity.h"
#include "log.h"
#include "secret.h"

#include "attestation/attestation_errors.h"
#include "attestation/sgx_challenger.h"

}

extern "C" int pcd_register_secret_to_remote(pcd_identity_t *data_owner_identity, const char *delegator_address, pcd_secret_t *input_secret) {
	ATTESTATION_STATUS ret_status;
	uint32_t challenger_session_id;
	size_t max_buffer_size;
	size_t output_buf_size;
	pcd_secret_req_t *secret_req;

	ret_status = create_session(&challenger_session_id, delegator_address);
	if (ret_status != SUCCESS) {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: create_session returned %d\n", ret_status);
		return -1;
	}

	if (input_secret->secret_size > 1024) {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: secret_size");
	}

	max_buffer_size = 1024 + sizeof(pcd_secret_req_t);
	secret_req = (pcd_secret_req_t *)malloc(max_buffer_size);
	if (secret_req == NULL) {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: failed to malloc secret request\n");
		return -1;
	}

	pcd_log("INFO: Sending %016llX's secret\n", ((uint64_t *)data_owner_identity)[0]);
	secret_req->req_type = PCD_SECRET_REQ_REGISTER;
	memcpy(&secret_req->id, data_owner_identity, sizeof(pcd_identity_t));
	memcpy(&secret_req->secret, input_secret, sizeof(pcd_secret_t) + input_secret->secret_size);

	ret_status = challenger_send_request_receive_response((uint8_t *)secret_req,
                                                 sizeof(pcd_secret_req_t) + input_secret->secret_size,
                                                 max_buffer_size,
                                                 (uint8_t *)secret_req,
                                                 &output_buf_size,
                                                 challenger_session_id, 
                                                 delegator_address);
	if (ret_status != SUCCESS) {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: challenger_send_request_receive_response returned %d\n", ret_status);
		free(secret_req);
		return -1;
	}

	if (secret_req->req_type == PCD_SECRET_REQ_RESPONSE_REG_OK) {
		// Good to go! Do nothing
	}
	else if (secret_req->req_type == PCD_SECRET_REQ_RESPONSE_DENINED) {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: secret registering denined from remote delegator");
		free(secret_req);
		return 2;
	}
	else {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: unexpected response");
		free(secret_req);
		return -1;
	}
	
	ret_status = close_session(challenger_session_id, delegator_address);
	if (ret_status != SUCCESS) {
		pcd_log_error("ERROR: pcd_sgx_register_secret_to_remote: close_session returned %d\n", ret_status);
		free(secret_req);
		return -1;
	}

	free(secret_req);

	return 0;
}
