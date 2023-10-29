/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// Enclave1.cpp : Defines the exported functions for the .so application
#include "sgx_eid.h"
#include "Enclave_t.h"
#include "error_codes.h"

#include "sgx_utils.h"

#include <stdio.h>
#include <string.h>

extern "C" {

#define PCD_CONFIG_CRYPTO_AES_GCM

#include "secret.h"

#include "secret_owner.h"

#include "policy/policy_def.h"

#include "crypto/aes_gcm.h"
#include "crypto/sha256.h"

#include "data_generator.h"

#include "policy_disc.h"
#include "user_data.h"
#include "attestation/sgx_challenger.h"
}

pcd_crypto_aes_gcm_key_t owner_encryption_key = {
	0x64, 0x52, 0x67, 0x55, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76, 0x38, 0x79, 0x2F, 0x42, 0x3F
};

sgx_measurement_t g_target_mrsigner = {
	{
		0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14, 0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
		0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c, 0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
	}
};

extern "C" uint32_t verify_peer_trust(sgx_dh_session_enclave_identity_t *peer_enclave_identity, int challenger_session_id) {
	if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_target_mrsigner, sizeof(sgx_measurement_t)))
		return 1;
	return 0;
}

extern "C" int printf(const char* fmt, ...) {
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print(buf);
	return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void pcd_policy_disc_print_hash(uint8_t *hash_ptr) {
	int i;
	for (i = 0; i < 32; i++) {
		printf("%02x", hash_ptr[i]);
	}
}

static void print_buffer(char *buffer, size_t size) {
	int i; int j;
	for (j = 0; j < size; ) {
		for (i = 0; i < 8; i++) {
			printf("%02X ", (unsigned char)buffer[j]);
			j++;
		}
		printf("\n");
	}
}

static bool init;

#define STATIC_DELEGATOR_ADDR "/tmp/UNIX0.domain"
static pcd_delegator_addr_t delegator_addr = STATIC_DELEGATOR_ADDR;

static pcd_policy_t *policy = NULL;
static pcd_demo_policy_rule_t demo_rules[3];

pcd_identity_t owner_id;

extern "C" int ecall_push_secret_to_remote() {
	pcd_secret_t *secret;
	int status;

	secret = (pcd_secret_t *)malloc(sizeof(pcd_secret_t) + sizeof(pcd_crypto_aes_gcm_key_t));
	if (secret == NULL) {
		printf("ERROR: ecall_push_secret_to_remote: Failed to allocate secret\n");
		return 1;
	}

	secret->secret_size = sizeof(pcd_crypto_aes_gcm_key_t);
	memcpy(&secret->secret, &owner_encryption_key, sizeof(pcd_crypto_aes_gcm_key_t));

	// send it to remtoe
	status = pcd_register_secret_to_remote(&owner_id, STATIC_DELEGATOR_ADDR, secret);

	return status;
}

extern "C" void pcd_print_id(char *id);

extern "C" int ecall_produce_data(uint64_t *numbers, uint64_t number_count, void *output_data, size_t *output_size, size_t max_size, uint8_t rule_mask) {
	int status;
	pcd_enc_data_t *enc_data;
	size_t data_size;
	user_data_t *input_data;
	size_t input_data_size;
	pcd_demo_attribute_t attributes;

	int rule_count = 0;
	int i;

	// Input data
	input_data_size = sizeof(user_data_t) + number_count * sizeof(uint64_t);
	input_data = (user_data_t *)malloc(input_data_size);
	if (input_data == NULL) {
		printf("ERROR: Consumer Enclave: Failed to allocate policy\n");
		return PCD_MEMERR;
	}
	printf("[+] number_count = %ld\n", number_count);
	input_data->count = number_count;
	for (i = 0; i < number_count; i++) {
		input_data->numbers[i] = numbers[i];
	printf("    [%d] = %ld\n", i, input_data->numbers[i]);
	}


	// Policy
	for (i = 0; i < 3; i++) {
		if ((rule_mask & (0x01 << i)) != 0) {
			rule_count += 1;
		}
	}

	policy = (pcd_policy_t *)malloc(sizeof(pcd_policy_t) + rule_count * sizeof(pcd_demo_policy_rule_t));
	if (policy == NULL) {
		printf("ERROR: Consumer Enclave: Failed to allocate policy\n");
		free(input_data);
		return PCD_MEMERR;
	}
	for (i = 0; i < 3; i++) {
		if ((rule_mask & (0x01 << i)) != 0) {
			memcpy((void *)(policy->policy_buffer + i * sizeof(pcd_demo_policy_rule_t)), 
				(void *)&(demo_rules[i]), sizeof(pcd_demo_policy_rule_t));
		}
	}

	memcpy((void *)&policy->type, (void *)&pcd_demo_policy_type, sizeof(pcd_policy_type_t));
	policy->policy_size = rule_count * sizeof(pcd_demo_policy_rule_t);

	// Attributes
	memcpy((void *)&attributes.custodian_id, &owner_id, sizeof(pcd_identity_t));
	attributes.number_of_entries = number_count;

	// Generate data
	status = pcd_generate_data((void *)input_data, input_data_size,
				&owner_id,
				&delegator_addr,
				policy,
				NULL, 0, // No tags
				&attributes, sizeof(pcd_demo_attribute_t),
				PCD_CRYPTO_AES_GCM,
				&enc_data);
	if (status != PCD_OK) {
		printf("ERROR: Producer Enclave: Failed to produce data with %d\n", status);
		free(input_data);
		free(policy);
		return status;
	}

	data_size = sizeof(pcd_enc_data_t) + enc_data->enc_size;
	if (data_size > max_size) {
		printf("ERROR: Producer Enclave: Failed to produce data due to size overflow\n");
		free(enc_data);
		free(input_data);
		free(policy);
		return 1;
	}

	memcpy(output_data, enc_data, data_size);
	*output_size = data_size;

	free(enc_data);
	free(input_data);
	free(policy);

	return 0;
}

pcd_secret_t *secret = NULL;

extern "C" void ecall_change_owner_id(uint8_t *new_owner_id) {
	memcpy((void *)&owner_id, (void *)new_owner_id, sizeof(pcd_identity_t));

	// As a demo, we use the same secret for everyone...
	pcd_secret_register(&owner_id, secret);
	memcpy((void *)&demo_rules[2].custodian_info.custodian_id, (void *)&owner_id, sizeof(pcd_identity_t));
}


extern "C" void ecall_change_target_hash(uint8_t *target_program_hash) {
	memcpy((void *)&demo_rules[0].program_hash, (void *)&target_program_hash, sizeof(pcd_sha256_t));
}

extern "C" void ecall_init_env(uint8_t *input_owner_id, uint8_t *target_program_hash) {
	pcd_crypto_init();
	set_enclave_trust_verifier(&verify_peer_trust);

	secret = (pcd_secret_t *)malloc(sizeof(pcd_secret_t) + sizeof(pcd_crypto_aes_gcm_key_t));
	secret->secret_size = sizeof(pcd_crypto_aes_gcm_key_t);
	memcpy(secret->secret, &owner_encryption_key, sizeof(pcd_crypto_aes_gcm_key_t));

	memcpy((void *)&owner_id, (void *)input_owner_id, sizeof(pcd_identity_t));

	pcd_secret_register(&owner_id, secret);

	demo_rules[0].rule_type = PCD_DEMO_POLICY_TYPE_PROGRAM_HASH;
	memcpy((void *)&demo_rules[0].program_hash, (void *)target_program_hash, sizeof(pcd_sha256_t));
	printf("[+] INFO: hash initied to be ");
	pcd_policy_disc_print_hash((uint8_t *)&demo_rules[0].program_hash);
	printf("\n");
	demo_rules[1].rule_type = PCD_DEMO_POLICY_TYPE_ENTRY_CAP;
	demo_rules[1].entry_cap_percentage = 70;
	demo_rules[2].rule_type = PCD_DEMO_POLICY_TYPE_PROGRAM_HASH;
	memcpy((void *)&demo_rules[2].custodian_info.custodian_id, (void *)&owner_id, sizeof(pcd_identity_t));
	demo_rules[2].custodian_info.entry_amount = 2;
}
