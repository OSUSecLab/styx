#include <sgx_tcrypto.h>

#include <error_codes.h>
#include <crypto/crypto.h>
#include <crypto/aes_gcm.h>

int pcd_crypto_backend_aes_gcm_decrypt(void *ciphertext, size_t cipher_size, void **plaintext, size_t *plain_size, 
					pcd_crypto_aes_gcm_metadata_t *metadata, pcd_crypto_aes_gcm_key_t *key) {
	sgx_status_t result;
	void *plaintext_buffer = malloc(cipher_size);

	*plaintext = NULL;
	*plain_size = 0;
	if (plaintext_buffer == NULL) {
		return PCD_MEMERR;
	}

	result = sgx_rijndael128GCM_decrypt(key, ciphertext, cipher_size, plaintext_buffer, metadata->iv, PCD_CRYPTO_AES_IV_LEN,
                                                metadata->aad, metadata->aad_size, &metadata->mac);
	
	switch (result) {
	case SGX_SUCCESS:
		*plain_size = cipher_size;
		*plaintext = plaintext_buffer;
		return PCD_OK;
	case SGX_ERROR_OUT_OF_MEMORY:
		return PCD_MEMERR;
	case SGX_ERROR_MAC_MISMATCH:
		return PCD_MAC_MISMATCH;
	default:
		return PCD_UNKNOWN;
	}
}

int pcd_crypto_backend_aes_gcm_encrypt(void *plaintext, size_t plain_size, void **ciphertext, size_t *cipher_size, 
					pcd_crypto_aes_gcm_metadata_t *metadata, pcd_crypto_aes_gcm_key_t *key) {
	sgx_status_t result;
	void *ciphertext_buffer = malloc(plain_size);

	*ciphertext = NULL;
	*cipher_size = 0;
	if (ciphertext_buffer == NULL) {
		return PCD_MEMERR;
	}

	result = sgx_rijndael128GCM_encrypt(key, plaintext, plain_size, ciphertext_buffer, metadata->iv, PCD_CRYPTO_AES_IV_LEN,
                                                metadata->aad, metadata->aad_size, &metadata->mac);

	switch (result) {
	case SGX_SUCCESS:
		*cipher_size = plain_size;
		*ciphertext = ciphertext_buffer;
		return PCD_OK;
	case SGX_ERROR_OUT_OF_MEMORY:
		return PCD_MEMERR;
	case SGX_ERROR_MAC_MISMATCH:
		return PCD_MAC_MISMATCH;
	default:
		return PCD_UNKNOWN;
	}
}

int pcd_crypto_backend_aes_gcm_verify(void *ciphertext, size_t cipher_size, pcd_crypto_aes_gcm_metadata_t *metadata, void *key) {
	sgx_status_t result;
	void *plaintext_buffer = malloc(cipher_size);

	if (plaintext_buffer == NULL) {
		return PCD_MEMERR;
	}

	result = sgx_rijndael128GCM_decrypt(key, ciphertext, cipher_size, plaintext_buffer, metadata->iv, PCD_CRYPTO_AES_IV_LEN,
                                                metadata->aad, metadata->aad_size, &metadata->mac);

	free(plaintext_buffer);
	
	switch (result) {
	case SGX_SUCCESS:
		return PCD_OK;
	case SGX_ERROR_OUT_OF_MEMORY:
		return PCD_MEMERR;
	case SGX_ERROR_MAC_MISMATCH:
		return PCD_MAC_MISMATCH;
	default:
		return PCD_UNKNOWN;
	}
}
