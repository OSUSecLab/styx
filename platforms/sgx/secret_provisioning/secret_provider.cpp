#include <cstdint>
#include <cstdlib>

extern "C" {

#include "identity.h"
#include "log.h"
#include "secret.h"

}

extern "C" uint32_t message_exchange_response_generator(uint8_t* decrypted_data,
                                              uint32_t decrypted_data_length,
                                              uint8_t** resp_buffer,
                                              size_t* resp_length) {
	pcd_secret_req_t *request = (pcd_secret_req_t *)decrypted_data;
	pcd_secret_req_t *resp;
	pcd_secret_t *retrieved_secret;
	size_t retrieved_secret_size;

	if (request->req_type != PCD_SECRET_REQ_REQUEST && request->req_type != PCD_SECRET_REQ_REGISTER) {
		// return a DENINED message
		pcd_log("INFO: Received wrong request type %d\n", request->req_type);
		resp = (pcd_secret_req_t *)malloc(sizeof(pcd_secret_req_t));
		if (resp == NULL) {
			pcd_log_error("ERROR: secret_provider: failed to allocate response\n");
			return -1;
		}
		resp->req_type = PCD_SECRET_REQ_RESPONSE_DENINED;
		*resp_buffer = (uint8_t *)resp;
		*resp_length = sizeof(pcd_secret_req_t);
		return 0;
	}

	if (request->req_type == PCD_SECRET_REQ_REQUEST) {
		if (pcd_secret_retrieve(&request->id, &retrieved_secret) != 0) {
			// Not found
			resp = (pcd_secret_req_t *)malloc(sizeof(pcd_secret_req_t));
			if (resp == NULL) {
				pcd_log_error("ERROR: secret_provider: failed to allocate response\n");
				return -1;
			}
			resp->req_type = PCD_SECRET_REQ_RESPONSE_NOT_FOUND;
			*resp_buffer = (uint8_t *)resp;
			*resp_length = sizeof(pcd_secret_req_t);
			return 0;
		}

		retrieved_secret_size = sizeof(pcd_secret_t) + retrieved_secret->secret_size;
		resp = (pcd_secret_req_t *)malloc(sizeof(pcd_secret_req_t) + retrieved_secret_size);
		if (resp == NULL) {
			pcd_log_error("ERROR: secret_provider: failed to allocate response\n");
			return -1;
		}
		resp->req_type = PCD_SECRET_REQ_RESPONSE_OK;
		memcpy(&resp->secret, retrieved_secret, retrieved_secret_size);

		pcd_secret_release(&request->id);

		*resp_buffer = (uint8_t *)resp;
		*resp_length = sizeof(pcd_secret_req_t) + retrieved_secret_size;

		return 0;
	}
	else if (request->req_type == PCD_SECRET_REQ_REGISTER) {
		resp = (pcd_secret_req_t *)malloc(sizeof(pcd_secret_req_t));
		if (resp == NULL) {
			pcd_log_error("ERROR: secret_provider: failed to allocate response\n");
			return -1;
		}
		pcd_log("INFO: Registering 0x%016llX\n", ((uint64_t *)(&request->id))[0]);
		if (pcd_secret_register(&request->id, &request->secret) != 0) {
			// REINIT!
			pcd_secret_release(&request->id);
			resp->req_type = PCD_SECRET_REQ_RESPONSE_DENINED;
			*resp_buffer = (uint8_t *)resp;
			*resp_length = sizeof(pcd_secret_req_t);
			return 0;
		}
		resp->req_type = PCD_SECRET_REQ_RESPONSE_REG_OK;
		*resp_buffer = (uint8_t *)resp;
		*resp_length = sizeof(pcd_secret_req_t);
		return 0;
	}
	pcd_log_error("ERROR: secret_provider: unknown request type\n");
	return -1;
}
