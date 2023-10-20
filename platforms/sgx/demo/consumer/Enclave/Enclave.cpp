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

#include "consumer.h"

#define PCD_CONFIG_POLICY_SIMPLE

#include "policy/policy.h"
#include "policy/simple.h"

#include "user_data.h"
#include "attestation/sgx_challenger.h"
}


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

static pcd_policy_simple_cred_t cred;
static bool init = false;

extern "C" uint32_t ecall_login(char *username, char *password) {
	// For demostration only!
	if (!strcmp(username, "user") && !strcmp(password, "passwd")) {
		cred = PCD_POLICY_SIMPLE_USER;
		pcd_consumer_register_credential(&cred, PCD_POLICY_SIMPLE);
		printf("INFO: Consumer Enclave: Logged in as user\n");
		return 0;
	}
	else if (!strcmp(username, "admin") && !strcmp(password, "passwd")) {
		cred = PCD_POLICY_SIMPLE_ADMIN;
		pcd_consumer_register_credential(&cred, PCD_POLICY_SIMPLE);
		printf("INFO: Consumer Enclave: Logged in as admin\n");
		return 0;
	}
	printf("ERROR: Consumer Enclave: Login failed!\n");
	return 1;
}

extern "C" uint32_t ecall_extract_and_print_data(void *input_data) {
	uint32_t status;
	user_data_t *output_data;
	size_t data_size;

	if (init == false) {
		printf("ERROR: Consumer Enclave: Uninitialised!\n");
		return 1;
	}

	printf("owner_id = 0x%016llX\n", ((uint64_t *)(&((pcd_enc_data_t *)input_data)->owner_id))[0]);

	status = pcd_consumer_extract_data((pcd_enc_data_t *)input_data, (void **)(&output_data), &data_size);
	if (status != PCD_OK) {
		printf("ERROR: Consumer Enclave: Failed to extract data with %d\n", status);
		return status;
	}

	switch(output_data->type) {
	case USER_DATA_TYPE_ORIGINAL:
		printf("INFO: Consumer Enclave: Data is %ld, %ld\n", output_data->numbers[0], output_data->numbers[1]);
		free(output_data);
		return 0;
	case USER_DATA_TYPE_RESULT:
		printf("INFO: Consumer Enclave: Data is %ld\n", output_data->numbers[0]);
		free(output_data);
		return 0;
	default:
		printf("ERROR: Consumer Enclave: Unknown data type %d\n", output_data->type);
		free(output_data);
		return 1;
	}
	free(output_data);
	return 1;
}

extern "C" void ecall_init_env() {
	pcd_policy_init();
	pcd_crypto_init();
	set_enclave_trust_verifier(&verify_peer_trust);
	init = true;
}
