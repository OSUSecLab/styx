#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "identity.h"
#include "data.h"
#include "log.h"
#include "error_codes.h"
#include "tag.h"

#include "crypto/crypto.h"
#include "policy/policy.h"
#include "policy/simple.h"

static uint8_t pcd_data_unpacker_generic_iv[16] = { [0 ... 15] = 0 };

int pcd_data_unpacker_decrypt_payload(void *enc_payload_with_mac, size_t enc_size_with_mac,
				pcd_identity_t *owner_id,
				pcd_crypto_algo_t crypto_algo, void *key,
				pcd_payload_t **payload) {
	pcd_crypto_algo_struct_t *algo;
	int status;
	size_t mac_size;
	void *mac = enc_payload_with_mac;
	size_t enc_size;
	void *enc_payload;
	void *metadata;
	size_t payload_size_dummy;

	algo = pcd_crypto_get_algo(crypto_algo);
	if (algo == NULL) {
		return PCD_CRYPTO_NSUPPORT;
	}

	// Generate metadata
	status = (*algo->generate_metadata)(pcd_data_unpacker_generic_iv, (uint8_t *)owner_id, sizeof(pcd_identity_t), mac, &metadata);
	if (status != PCD_OK) {
		return status;
	}
	
	pcd_log("algo is %d\n", crypto_algo);
	// Get MAC size and set enc_payload
	mac_size = algo->mac_size;
	enc_payload = enc_payload_with_mac + mac_size;
	enc_size = enc_size_with_mac - mac_size;
	
	// Decrypt
	status = (*algo->decrypt)(enc_payload, enc_size, (void **)payload, &payload_size_dummy, metadata, key);
	if (status != PCD_OK) {
		free(metadata);
		return status;
	}

	// Free metadata
	free(metadata);

	return PCD_OK;
}

static void print_buffer(char *buffer, size_t size) {
	int i; int j;
	for (j = 0; j < size; ) {
		for (i = 0; i < 8; i++) {
			pcd_log("%02X ", (unsigned char)buffer[j]);
			j++;
		}
		pcd_log("\n");
	}
}

int pcd_data_unpacker_extract_data(pcd_enc_data_t *input_data,
				void **output_data, size_t *data_size,
				pcd_policy_t **output_policy, 
				pcd_tag_t **output_tags, uint32_t *tag_count,
				pcd_identity_t *owner_id, void *key) {
	void *tmp_data;
	pcd_policy_t *policy;
	pcd_tag_t *tags;
	pcd_crypto_algo_t crypto_algo;
	
	size_t total_size;
	size_t tmp_data_size;
	size_t policy_size;
	size_t tag_size;

	pcd_payload_t *plain_payload;
	int status;
	int i;

	if (input_data == NULL || output_data == NULL|| data_size == NULL
		|| output_policy == NULL || output_tags == NULL || tag_count == NULL 
		|| owner_id == NULL) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Parameter is NULL\n");
		return PCD_NULL_ARG;
	}
	*output_data = NULL;

	// Decrypt encrypted data with mac
	status = pcd_data_unpacker_decrypt_payload(input_data->encrypted_payload, input_data->enc_size,
				&input_data->owner_id,
				input_data->enc_algo, key,
				&plain_payload);
	if (status != PCD_OK) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Failed to decrypt with %d\n", status);
		return status;
	}
	tmp_data_size = plain_payload->data_size;
	policy_size = plain_payload->policy_size;
	tag_size = plain_payload->tag_size;

	print_buffer((char *)plain_payload, sizeof(pcd_payload_t) + tmp_data_size + policy_size + tag_size);

	// Allocate output
	if (tag_size % sizeof(pcd_tag_t) != 0) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Unexpected tag size");
		free(plain_payload);
		return PCD_UNKNOWN;
	}

	tmp_data = malloc(tmp_data_size);
	if (tmp_data == NULL) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Failed to allocate data");
		free(plain_payload);
		return PCD_MEMERR;
	}

	policy = (pcd_policy_t *)malloc(policy_size);
	if (policy == NULL) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Failed to allocate policy");
		free(tmp_data);
		free(plain_payload);
		return PCD_MEMERR;
	}

	tags = (pcd_tag_t *)malloc(tag_size);
	if (tags == NULL) {
		pcd_log_error("ERROR: pcd_data_pcaker_generate_data: Failed to allocate tags");
		free(policy);
		free(tmp_data);
		free(plain_payload);
		return PCD_MEMERR;
	}
	pcd_log("INFO: tmp_data_size = %d\n", tmp_data_size);
	pcd_log("INFO: policy_size = %d\n", policy_size);
	pcd_log("INFO: tags size = %d\n", tag_size);

	memcpy(owner_id, &input_data->owner_id, sizeof(pcd_identity_t));
	memcpy(tmp_data, plain_payload->payload, tmp_data_size);
	memcpy(policy, plain_payload->payload + tmp_data_size, policy_size);
	memcpy(tags, plain_payload->payload + tmp_data_size + policy_size, tag_size);

	free(plain_payload);

	*output_data = tmp_data;
	*data_size = tmp_data_size;
	*output_policy = policy;
	*output_tags = tags;
	*tag_count = tag_size / sizeof(pcd_tag_t);

	return PCD_OK;
}
