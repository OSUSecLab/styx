#ifndef _PCD_CRYPTO_SHA256_BACKEND_H_
#define _PCD_CRYPTO_SHA256_BACKEND_H_

#include <stdint.h>

#include "crypto/sha256.h"

int pcd_crypto_backend_sha256_hash_buffer(uint8_t *buffer, size_t size, pcd_sha256_t *output_hash);

#endif