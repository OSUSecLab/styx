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

#include "runtime.h"
#include "app.h"
#include "policy/policy.h"

#include "secret.h"

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

static bool init = false;

pcd_secret_t *secret = NULL;
char global_demo_encryption_key[16] = {
	0x64, 0x52, 0x67, 0x55, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76, 0x38, 0x79, 0x2F, 0x42, 0x3F
};

extern "C" int ecall_run_app(uint8_t *app_module_buffer, uint32_t app_module_size, char *custodian_id,
				char **dir_allow_list, uint32_t dir_allow_count, 
				uint32_t stack_size, uint32_t heap_size, uint32_t *argv, uint32_t argc) {
	int ret;
	char **dir_allow_list_in_enclave;
	int i;

	dir_allow_list_in_enclave = (char **)malloc(sizeof(char *) * dir_allow_count);
	for (i = 0; i < dir_allow_count; i++) {
		dir_allow_list_in_enclave[i] = (char *)malloc(strlen(dir_allow_list[i] + 1));
		strncpy(dir_allow_list_in_enclave[i], dir_allow_list[i], strlen(dir_allow_list[i]) + 1);
	}

	ret = pcd_app_load(app_module_buffer, app_module_size, (pcd_identity_t *)custodian_id);
	if (ret != PCD_OK) {
		printf("[-] Middleware: ERROR: Failed to load app with %d\n", ret);
		return ret;
	}
	printf("[+] Middleware: INFO: App loaded\n");

	secret = (pcd_secret_t *)malloc(sizeof(pcd_secret_t) + 16);
	if (secret == NULL) {
		printf("[-] Middleware: ERROR: Failed allocate secret\n");
		return -1;
	}
	secret->secret_size = 16;
	memcpy(secret->secret, &global_demo_encryption_key, 16);

	pcd_secret_register((pcd_identity_t *)custodian_id, secret);
	free(secret);
	printf("[+] Middleware: INFO: Secret registered\n");

	printf("DEBUG: dir_allow: %s\n", dir_allow_list_in_enclave[0]);
	ret = pcd_app_run((const char **)dir_allow_list_in_enclave, dir_allow_count, stack_size, heap_size, argv, argc);
	if (ret != PCD_OK) {
		printf("[-] Middleware: ERROR: Failed to run app with %d\n", ret);
		return ret;
	}
	printf("[+] Middleware: INFO: App finished\n");

	ret = pcd_app_unload();
	if (ret != PCD_OK) {
		printf("[-] Middleware: ERROR: Failed to unload app with %d\n", ret);
		return ret;
	}
	printf("[+] Middleware: INFO: App unloaded\n");

	return ret;
}

extern "C" int ecall_load_disc(char *module_buffer, size_t module_size, char *type) {
	int ret;
	ret = pcd_policy_load_disc(module_buffer, module_size, (pcd_policy_type_t *)type);
	if (ret != PCD_OK) {
		printf("[-] Middleware: ERROR: Failed to load disc with %d\n", ret);
	}
	return ret;
}



#ifdef PCD_DEMO_USE_NATIVE_LIBONNX
extern "C" {
uint32_t pcd_wamr_register_native_symbol(const char *name, void *ptr, const char *signature);
int onnx_get_graph_nlen(void * ctx);
pcd_runtime_pointer_t onnx_benchmark_get_name(void * ctx, int i);
void onnx_run_single_node(void * ctx, int i);
pcd_runtime_pointer_t onnx_context_alloc(const void * buf, size_t len, void ** r, int rlen);
void onnx_context_free(void * ctx);

int onnx_get_graph_nlen_wrapper(wasm_exec_env_t exec_env, void *ctx) {
	return onnx_get_graph_nlen(ctx);
}

pcd_runtime_pointer_t onnx_benchmark_get_name_wrapper(wasm_exec_env_t exec_env, void * ctx, int i) {
	return onnx_benchmark_get_name(ctx, i);
}

void onnx_run_single_node_wrapper(wasm_exec_env_t exec_env, void * ctx, int i) {
	onnx_run_single_node(ctx, i);
}

pcd_runtime_pointer_t onnx_context_alloc_wrapper(wasm_exec_env_t exec_env, const void * buf, size_t len, void ** r, int rlen) {
	return onnx_context_alloc(buf, len, r, rlen);
}

void onnx_context_free_wrapper(wasm_exec_env_t exec_env, void * ctx) {
	onnx_context_free(ctx);
}
}
#endif

#ifdef PCD_DEMO_USE_LIBSVM

#include <svm.h>

extern "C" {

int svm_check_parameter_wrapper(wasm_exec_env_t exec_env, const struct svm_problem *prob, const struct svm_parameter *param) {
	return svm_check_parameter(prob, param);
}

uint64_t svm_train_wrapper(wasm_exec_env_t exec_env, const struct svm_problem *prob, const struct svm_parameter *param) {
	return (uint64_t)(svm_train(prob, param));
}

void svm_free_and_destroy_model_wrapper(wasm_exec_env_t exec_env, struct svm_model **model_ptr_ptr) {
	svm_free_and_destroy_model(model_ptr_ptr);
}

void svm_destroy_param_wrapper(wasm_exec_env_t exec_env, struct svm_parameter *param) {
	svm_destroy_param(param);
}


pcd_runtime_pointer_t svm_new_param(wasm_exec_env_t exec_env) {
	pcd_instance_t *instance = (pcd_instance_t *)(wasm_runtime_get_module_inst(exec_env));
	struct svm_parameter *param = NULL;
	pcd_runtime_pointer_t app_param;

	app_param = pcd_runtime_malloc(instance, sizeof(struct svm_parameter), (void **)&param);
	if (param == NULL) {
		printf("Error: svm_init_param: Failed to allocate parameters\n");
		return 0;
	}

	param->svm_type = C_SVC;
	param->kernel_type = RBF;
	param->degree = 3;
	param->gamma = 0;	// 1/num_features
	param->coef0 = 0;
	param->nu = 0.5;
	param->cache_size = 100;
	param->C = 1;
	param->eps = 1e-3;
	param->p = 0.1;
	param->shrinking = 1;
	param->probability = 0;
	param->nr_weight = 0;
	param->weight_label = NULL;
	param->weight = NULL;

	return app_param;
}

void svm_free_param(wasm_exec_env_t exec_env, struct svm_parameter *param) {
	pcd_instance_t *instance = (pcd_instance_t *)(wasm_runtime_get_module_inst(exec_env));

	pcd_runtime_free(instance, pcd_runtime_native_to_app(instance, param));
}

void svm_free_problem(wasm_exec_env_t exec_env, struct svm_problem *prob) {
	pcd_instance_t *instance = (pcd_instance_t *)(wasm_runtime_get_module_inst(exec_env));
	if (prob->x != NULL) {
		if (prob->x[0] != NULL) {
			// x_space
			free(prob->x[0]);
		}
		free(prob->x);
	}
	if (prob->y != NULL) {
		free(prob->y);
	}

	pcd_runtime_free(instance, pcd_runtime_native_to_app(instance, prob));
}

pcd_runtime_pointer_t svm_dataset_to_problem(wasm_exec_env_t exec_env, pcd_runtime_pointer_t *feature_vectors, pcd_runtime_pointer_t *labels, int *record_counts, int datasets, int feature_vector_length, struct svm_parameter *param) {
	int dataset_iterator, record_iterator, global_record_iterator = 0;
	int feature_iterator;
	pcd_runtime_pointer_t app_feature_vector;
	pcd_runtime_pointer_t app_label;
	int record_count;
	double *feature_vector;
	double *label;
	int total_record_count = 0;
	pcd_instance_t *instance = (pcd_instance_t *)(wasm_runtime_get_module_inst(exec_env));

	struct svm_problem *prob = NULL;
	pcd_runtime_pointer_t app_prob;
	struct svm_node *x_space = NULL;
	
	// Count total records of all datasets
	for (dataset_iterator = 0; dataset_iterator < datasets; dataset_iterator++) {
		total_record_count += record_counts[dataset_iterator];
	}

	// Allocate problem
	app_prob = pcd_runtime_malloc(instance, sizeof(struct svm_problem), (void **)&prob);
	if (prob == NULL) {
		printf("Error: svm_dataset_to_problem: failed to allocate problem\n");
		goto error_out;
	}
	prob->l = total_record_count;
	//printf("[?] INFO: total records: %d\n", total_record_count);
	prob->y = (double *)malloc(sizeof(double) * total_record_count);
	if (prob->y == NULL) {
		printf("Error: svm_dataset_to_problem: failed to allocate prob->y\n");
		goto error_prob;
	}
	prob->x = (struct svm_node **)malloc(sizeof(struct svm_node *) * total_record_count);
	if (prob->x == NULL) {
		printf("Error: svm_dataset_to_problem: failed to allocate prob->x\n");
		goto error_y;
	}
	// feature_vector_length + 1 is because each feature vector must end with an extra -1
	x_space = (struct svm_node *)malloc(sizeof(struct svm_node) * (feature_vector_length + 1) * total_record_count);
	if (x_space == NULL) {
		printf("Error: svm_dataset_to_problem: failed to allocate x_space\n");
		goto error_x;
	}

	for (dataset_iterator = 0; dataset_iterator < datasets; dataset_iterator++) {
		app_feature_vector = feature_vectors[dataset_iterator];
		app_label = labels[dataset_iterator];
		record_count = record_counts[dataset_iterator];

		feature_vector = (double *)pcd_runtime_app_to_native(instance, app_feature_vector);
		label = (double *)pcd_runtime_app_to_native(instance, app_label);

		for (record_iterator = 0; record_iterator < record_count; record_iterator++) {
			// Set label
			prob->y[global_record_iterator] = label[record_iterator];

			// Set feature vector
			prob->x[global_record_iterator] = &(x_space[global_record_iterator * (feature_vector_length + 1)]);
			for (feature_iterator = 0; feature_iterator < feature_vector_length; feature_iterator++) {
				x_space[global_record_iterator * (feature_vector_length + 1) + feature_iterator].index = feature_iterator + 1;
				x_space[global_record_iterator * (feature_vector_length + 1) + feature_iterator].value = feature_vector[record_iterator * feature_vector_length + feature_iterator];
			}
			x_space[global_record_iterator * (feature_vector_length + 1) + feature_vector_length].index = -1;
			global_record_iterator += 1;
		}

	}

	if(param->gamma == 0)
		param->gamma = 1.0 / feature_vector_length;

	return app_prob;

error_x_space:
	free(x_space);
error_x:
	free(prob->x);
error_y:
	free(prob->y);
error_prob:
	pcd_runtime_free(instance, app_prob);
error_out:
	return 0;
}

}

#endif

extern "C" {
static struct native_symbol {
	const char *name;
	void *ptr;
	const char *signature;
} pcd_dataset_native_symbols[] = 
{
#ifdef PCD_DEMO_USE_NATIVE_LIBONNX
	{ "onnx_get_graph_nlen", 		(void*)onnx_get_graph_nlen_wrapper,	"(*)i" },
	{ "onnx_benchmark_get_name", 	(void*)onnx_benchmark_get_name_wrapper, "(*i)i" },
	{ "onnx_run_single_node", 		(void*)onnx_run_single_node_wrapper, 	"(*i)" },
	{ "onnx_context_alloc", 		(void*)onnx_context_alloc_wrapper, 	"(*i*i)i" },
	{ "onnx_context_free", 		(void*)onnx_context_free_wrapper, 	"(*)" },
#endif

#ifdef PCD_DEMO_USE_LIBSVM
	{ "svm_free_and_destroy_model",	(void*)svm_free_and_destroy_model_wrapper,	"(*)" },
	{ "svm_destroy_param",		(void*)svm_destroy_param_wrapper,	"(*)" },
	{ "svm_train",			(void*)svm_train_wrapper,		"(**)I" },
	{ "svm_check_parameter",	(void*)svm_check_parameter_wrapper,	"(**)i" },
	{ "svm_new_param", 		(void*)svm_new_param,			"()i" },
	{ "svm_free_param", 		(void*)svm_free_param,			"(*)" },
	{ "svm_free_problem", 		(void*)svm_free_problem,		"(*)" },
	{ "svm_dataset_to_problem", 	(void*)svm_dataset_to_problem,		"(***ii*)i" },
	{ "svm_save_model", 		(void*)svm_save_model,			"(Ii*)i" },
#endif
};
}

int register_native_symbols() {
	// 5 APIs needed to run benchmark
	int i;
	int ret = 0;

	for (i = 0; i < (sizeof(pcd_dataset_native_symbols) / sizeof(struct native_symbol)); i++) {
		if ((ret = pcd_wamr_register_native_symbol(
			pcd_dataset_native_symbols[i].name,
			pcd_dataset_native_symbols[i].ptr,
			pcd_dataset_native_symbols[i].signature
		))) {
			printf("Error: Failed to register native symbol %s", pcd_dataset_native_symbols[i].name);
			return ret;
		}
	}
	return 0;
}

extern "C" void ecall_init_env() {
	pcd_runtime_setup_environment();
	// Add library symbols
	register_native_symbols();
	pcd_crypto_init();
	set_enclave_trust_verifier(&verify_peer_trust);

	init = true;
}
