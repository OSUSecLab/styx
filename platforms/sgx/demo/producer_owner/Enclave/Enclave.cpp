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

#define PCD_CONFIG_POLICY_SIMPLE
#define PCD_CONFIG_CRYPTO_AES_GCM

#include "producer.h"
#include "secret.h"

#include "secret_owner.h"

#include "policy/policy.h"
#include "policy/simple.h"

#include "crypto/aes_gcm.h"

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

static pcd_policy_simple_cred_t cred;
static bool init;

#define STATIC_DELEGATOR_ADDR "/tmp/UNIX0.domain"
static pcd_delegator_addr_t delegator_addr = STATIC_DELEGATOR_ADDR;

static pcd_policy_t *policy;
static pcd_policy_simple_policy_t *simple_policy;
static pcd_policy_simple_rule_t simple_rules[3] = {
	{ static_original_type, PCD_POLICY_SIMPLE_ADMIN },
	{ static_result_type, PCD_POLICY_SIMPLE_USER },
	{ static_result_type, PCD_POLICY_SIMPLE_ADMIN }
};

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
	status = pcd_register_secret_to_remote(&static_owner_id, STATIC_DELEGATOR_ADDR, secret);

	return status;
}

extern "C" int ecall_produce_data(uint64_t a, uint64_t b, void *output_data, size_t *output_size, size_t max_size) {
	int status;
	pcd_enc_data_t *enc_data;
	size_t data_size;
	user_data_t input_data;

	input_data.type = USER_DATA_TYPE_ORIGINAL;
	input_data.numbers[0] = a;
	input_data.numbers[1] = b;

	status =  pcd_producer_generate_data((void *)&input_data, sizeof(input_data), &static_original_type, 1, &enc_data);
	if (status != PCD_OK) {
		printf("ERROR: Consumer Enclave: Failed to produce data with %d\n", status);
		return status;
	}

	data_size = sizeof(pcd_enc_data_t) + enc_data->enc_size;
	if (data_size > max_size) {
		printf("ERROR: Consumer Enclave: Failed to produce data due to size overflow\n");
		free(enc_data);
		return 1;
	}

	memcpy(output_data, enc_data, data_size);
	*output_size = data_size;

	free(enc_data);
	return 0;
}

extern "C" void ecall_init_env() {
	pcd_policy_init();
	pcd_crypto_init();
	set_enclave_trust_verifier(&verify_peer_trust);

	simple_policy = (pcd_policy_simple_policy_t *)malloc(sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules));
	memcpy((void *)&simple_policy->rules, (void *)&simple_rules, sizeof(simple_rules));
	simple_policy->rule_count = 3;
	printf("INFO: simple_policy size is %ld\n", sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules));

    print_buffer((char *)simple_policy, sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules));

	policy = (pcd_policy_t *)malloc(sizeof(pcd_policy_t) + sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules));
	memcpy((void *)&policy->policy_buffer, (void *)simple_policy, sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules));
	policy->type = PCD_POLICY_SIMPLE;
	policy->policy_size = sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules);
	printf("INFO: policy size is %ld\n", sizeof(pcd_policy_t) + sizeof(pcd_policy_simple_policy_t) + sizeof(simple_rules));

	print_buffer((char *)policy, sizeof(pcd_policy_t) + policy->policy_size);

	pcd_producer_init(&static_owner_id, policy, &delegator_addr,
			 &owner_encryption_key, PCD_CRYPTO_AES_GCM);
}
