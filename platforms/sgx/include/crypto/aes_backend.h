#ifndef _SGX_AES_H_
#define _SGX_AES_H_

#include <sgx_tcrypto.h>

int pcd_crypto_backend_aes_gcm_decrypt(void *ciphertext, size_t cipher_size, void **plaintext, size_t *plain_size, 
					pcd_crypto_aes_gcm_metadata_t *metadata, pcd_crypto_aes_gcm_key_t *key);
int pcd_crypto_backend_aes_gcm_encrypt(void *plaintext, size_t plain_size, void **ciphertext, size_t *cipher_size, 
					pcd_crypto_aes_gcm_metadata_t *metadata, pcd_crypto_aes_gcm_key_t *key);
int pcd_crypto_backend_aes_gcm_verify(void *ciphertext, size_t cipher_size, pcd_crypto_aes_gcm_metadata_t *metadata, void *key);

#endif
