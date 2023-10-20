#ifndef _PCD_DATA_H_
#define _PCD_DATA_H_

#include <stdint.h>

#include "identity.h"
#include <crypto/crypto.h>

typedef uint64_t pcd_protocol_version_t;

#define PCD_PROTOCOL_VERSION		0
#define PCD_DELEGATOR_ADDR_MAX_LEN	64

typedef char pcd_delegator_addr_t[PCD_DELEGATOR_ADDR_MAX_LEN];

// Capsulated encrypted data
typedef struct pcd_enc_data {
	pcd_protocol_version_t protocol_version;
	pcd_identity_t owner_id;
	pcd_crypto_algo_t enc_algo;
	uint64_t enc_size;
	pcd_delegator_addr_t delegator_addr;

	// Encrypted payload
	uint8_t encrypted_payload[];
} __attribute__((packed)) pcd_enc_data_t;

// Plaintext payload before encryption
typedef struct pcd_payload {
	// Data + Policy + Tags
	size_t data_size;
	size_t policy_size;
	size_t tag_size;

	uint8_t payload[];
} __attribute__((packed)) pcd_payload_t;


#endif
