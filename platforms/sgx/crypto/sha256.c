#include "sgx_tcrypto.h"

#include "log.h"

#include "crypto/sha256.h"

int pcd_crypto_backend_sha256_hash_buffer(uint8_t *buffer, size_t size, pcd_sha256_t *output_hash) {
	sgx_sha_state_handle_t sha_context;
	sgx_status_t sgx_ret = SGX_SUCCESS;

	sgx_ret = sgx_sha256_init(&sha_context);
	if (sgx_ret != SGX_SUCCESS) {
		pcd_log_error("ERROR: pcd_crypto_backend_sha256_hash_buffer: Failed to sgx_sha256_init with %d\n", sgx_ret);
		return -1;
	}

	sgx_ret = sgx_sha256_update(buffer, size, sha_context);
	if (sgx_ret != SGX_SUCCESS) {
		pcd_log_error("ERROR: pcd_crypto_backend_sha256_hash_buffer: Failed to sgx_sha256_update with %d\n", sgx_ret);
		sgx_sha256_close(sha_context);
		return -1;
	}

	sgx_ret = sgx_sha256_get_hash(sha_context, (sgx_sha256_hash_t *)output_hash);
	if (sgx_ret != SGX_SUCCESS) {
		pcd_log_error("ERROR: pcd_crypto_backend_sha256_hash_buffer: Failed to sgx_sha256_get_hash with %d\n", sgx_ret);
		sgx_sha256_close(sha_context);
		return -1;
	}

	sgx_sha256_close(sha_context);

	return 0;
} 