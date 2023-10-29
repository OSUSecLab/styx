#include <stdint.h>

#include "crypto/sha256.h"

int pcd_crypto_sha256_hash_buffer(uint8_t *buffer, size_t size, pcd_sha256_t *output_hash) {
	return pcd_crypto_backend_sha256_hash_buffer(buffer, size, output_hash);
}