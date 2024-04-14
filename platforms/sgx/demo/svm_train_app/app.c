#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <errno.h>

#include "svm_data.h"
#include "policy_disc.h"

#include "identity.h"

#include "data.h"
#include "dataset.h"
#include "error_codes.h"

#include "data_generator_consumer.h"

uint64_t time_discrepancy;

static inline uint64_t time_get(void)
{
	struct timeval tv;

	gettimeofday(&tv, 0);
	return (uint64_t)(tv.tv_sec * 1000000000ULL + tv.tv_usec * 1000);
}

extern char *read_file_to_buffer(const char *filename, size_t *ret_size);

pcd_identity_t *owner_id = NULL;

char cmdbuffer[100];

#define DATA_MAX_COUNT	10

void builtin_free(void *ptr) __attribute__((
	__import_module__("env"),
	__import_name__("free")
));

void *svm_new_param();
void *svm_dataset_to_problem(double **feature_vectors, double **labels, int *record_counts, int datasets, int feature_vector_length, void *param);
void svm_free_problem(void *prob);
void svm_free_param(void *param);
int svm_check_parameter(void *prob, void *param);
void svm_free_and_destroy_model(uint64_t *model_ptr_ptr);
void svm_destroy_param(void *param);
uint64_t svm_train(void *prob, void *param);
char *svm_save_model(uint64_t model_ptr, int feature_length, int *saved_size);

#define STATIC_DELEGATOR_ADDR "/tmp/UNIX0.domain"
static pcd_delegator_addr_t delegator_addr = STATIC_DELEGATOR_ADDR;

void process_data_and_output(uint32_t dataset_index, uint32_t data_count) {
	int i;
	pcd_payload_t *payload;
	uint8_t *data_accessor;
	svm_data_t *svm_data;
	double *x_data[DATA_MAX_COUNT];
	double *y_data[DATA_MAX_COUNT];
	pcd_payload_t *free_list[DATA_MAX_COUNT];
	int record_counts[DATA_MAX_COUNT];
	void *param;
	void *problem;
	uint64_t model_native_ptr; 
	int feature_vector_length = -1;
	int param_err;
	char *saved_model;
	int saved_size;
	pcd_policy_t *policy = NULL;
	pcd_demo_attribute_t attributes;
	pcd_demo_policy_rule_t demo_rule;
	int status;
	uint64_t time_start;
	uint64_t time_end;

	for (i = 0; i < data_count; i++) {
		payload = (pcd_payload_t *)pcd_dataset_access(dataset_index, i);
		time_start = time_get();
		free_list[i] = payload;
		data_accessor = (uint8_t *)payload;
		if (payload == NULL) {
			printf("[-] WASM App: ERROR: Failed to access dataset %d's data %d\n", dataset_index, i);
			return;
		}

		svm_data = (svm_data_t *)payload->payload;
		//printf("[+] WASM App: DEBUG: Data %d has %llu records\n", i, svm_data->record_count);
		if (payload->data_size != (svm_data->record_count * (sizeof(double) * (svm_data->feature_vector_length + 1))+ sizeof(svm_data_t))) {
			printf("[-]  size mismatch!\n");
			return;
		}
		else {
			if (feature_vector_length == -1) {
				feature_vector_length = svm_data->feature_vector_length;
				//printf("[!] feature_vector_length = %d\n", feature_vector_length);
			}

			if (svm_data->feature_vector_length != feature_vector_length) {
				printf("[-] Dataset %d feature vector length (%llu) mismatch (should be %d)", i, svm_data->feature_vector_length, feature_vector_length);
			}
			else {
				// Build training sets
				x_data[i] = &(svm_data->numbers[0]);
				y_data[i] = &(svm_data->numbers[svm_data->feature_vector_length *  svm_data->record_count]);
				record_counts[i] = (int)(svm_data->record_count);
			}
		}

		time_end = time_get() - time_discrepancy;
		printf("[!] Add to training set cost %llu\n", time_end - time_start);
	}

	time_start = time_get();
	// New param
	param = svm_new_param();
	if (param == NULL) {
		printf("[-] param is NULL\n");
		return;
	}

	// Build problem
	problem = svm_dataset_to_problem(x_data, y_data, record_counts, data_count, feature_vector_length, param);
	if (param == NULL) {
		printf("[-] problem is NULL\n");
		svm_free_param(param);
		return;
	}

	param_err = svm_check_parameter(problem, param);
	if (param_err != 0) {
		printf("[-] parameter wrong with %d\n", param_err);
		svm_free_param(param);
		return;
	}
	time_end = time_get() - time_discrepancy;
	printf("[!] Initialisation cost %llu\n", time_end - time_start);

	// Train model
	time_start = time_get();
	model_native_ptr = svm_train(problem, param);
	if (model_native_ptr == 0) {
		printf("[-] model is NULL\n");
		svm_free_param(param);
		svm_free_problem(problem);
	}
	time_end = time_get() - time_discrepancy;
	printf("[!] Training cost %llu\n", time_end - time_start);

	// Save model
	time_start = time_get();
	saved_model = svm_save_model(model_native_ptr, feature_vector_length, &saved_size);
	if (saved_model == NULL) {
		printf("[-] Saved model is NULL\n");
	}
	else {
		printf("[+] Saved size = %d\n", saved_size);
	}
	time_end = time_get() - time_discrepancy;
	printf("[!] Model serialisation cost %llu\n", time_end - time_start);

	// A demo 1 rule policy
	time_start = time_get();
	policy = (pcd_policy_t *)malloc(sizeof(pcd_policy_t) + sizeof(pcd_demo_policy_rule_t));
	if (policy == NULL) {
		printf("ERROR: Consumer Enclave: Failed to allocate policy\n");
		goto error_fail_to_save;
	}
	demo_rule.rule_type = PCD_DEMO_POLICY_TYPE_CUSTODIAN;
	memcpy(&demo_rule.custodian_id, owner_id, sizeof(pcd_identity_t));
	memcpy((void *)(policy->policy_buffer), (void *)&(demo_rule), sizeof(pcd_demo_policy_rule_t));

	memcpy((void *)&policy->type, (void *)&pcd_demo_policy_type, sizeof(pcd_policy_type_t));
	policy->policy_size = sizeof(pcd_demo_policy_rule_t);

	memcpy(&attributes.custodian_id, owner_id, sizeof(pcd_identity_t));
	attributes.number_of_entries = 0;

	status = pcd_consumer_generate_data((void *)saved_model, saved_size,
				owner_id,
				&delegator_addr,
				policy,
				NULL, 0, // No tags
				&attributes, sizeof(pcd_demo_attribute_t),
				PCD_CRYPTO_AES_GCM,
				"../svm_model.model");
	if (status != PCD_OK) {
		printf("[-] ERROR: Failed to save model with %d\n", status);
	}
	time_end = time_get() - time_discrepancy;
	printf("[!] Model PAD generation cost %llu\n", time_end - time_start);

	printf("[+] INFO: Saved model to ../svm_model.model");

error_fail_to_save:
	time_start = time_get();
	for (i = 0; i < data_count; i++) {
		builtin_free(free_list[i]);
	}

	svm_free_and_destroy_model(&model_native_ptr);
	svm_destroy_param(param);
	svm_free_param(param);
	svm_free_problem(problem);

	time_end = time_get() - time_discrepancy;
	printf("[!] Cleanup cost %llu\n", time_end - time_start);

	printf("[+] WASM App: DEBUG: Done training\n");
}

void pcd_policy_disc_print_id(pcd_identity_t *id) {
	uint8_t *id_ptr = (uint8_t *)id;
	int i;
	printf("%08x-", ((uint32_t*)(id_ptr))[0]);
	printf("%04x-", *((uint16_t*)(&id_ptr[4])));
	printf("%04x-", *((uint16_t*)(&id_ptr[6])));
	for (i = 8; i < 10; i++) {
		printf("%02x", id_ptr[i]);
	}
	printf("-");
	for (i = 10; i < 16; i++) {
		printf("%02x", id_ptr[i]);
	}
}

int main() {
	uint32_t dataset_index;
	uint32_t ret;
	pcd_enc_data_t *enc_data = NULL;
	size_t enc_data_size;
	uint32_t data_count = 0;
	int i;
	size_t owner_id_size;

	uint64_t time_diff[6];
	

	time_diff[0] = time_get();
	time_diff[1] = time_get();
	time_diff[2] = time_get();
	time_diff[3] = time_get();
	time_diff[4] = time_get();
	time_diff[5] = time_get();
	for (i = 0; i < 5; i++) {
		time_discrepancy += time_diff[i + 1] - time_diff[i];
	}
	time_discrepancy /= 5;
	
	printf("Enter owner ID path: ");
	fflush(stdout);
	scanf("%s", cmdbuffer);		
	owner_id = (pcd_identity_t *)read_file_to_buffer(cmdbuffer, &owner_id_size);
	if (owner_id == NULL) {
		printf("[-] WASM App: ERROR: Failed to read owner ID %s\n", cmdbuffer);
		return -1;
	}
	if (owner_id_size != sizeof(pcd_identity_t)) {
		printf("[-] WASM App: ERROR: Wrong owner ID size %zu vs %lu\n", owner_id_size, sizeof(pcd_identity_t));
		builtin_free(owner_id);
		return -1;
	}

	printf("[+] Owner ID set: ");
	pcd_policy_disc_print_id(owner_id);
	printf("\n");

	dataset_index = pcd_dataset_new(DATA_MAX_COUNT);
	if (((int)dataset_index) < 0) {
		printf("[-] WASM App: ERROR: Failed to create new dataset with %d\n", (int)dataset_index);
		return (int)dataset_index;
	}


	printf("[+] Dataset %d ready\n", dataset_index);

	while (1) {
		printf("Enter command: ");
		fflush(stdout);
		scanf("%s", cmdbuffer);
		if (cmdbuffer[1] != 0) {
			printf("Error: Unknown command\n");
			continue;
		}

		switch (cmdbuffer[0]) {
		case 'l':
			scanf("%s", cmdbuffer);
			if (data_count > DATA_MAX_COUNT) {
				printf("[-] WASM App: ERROR: Already reached maximum data in dataset\n");
				break;
			}
			enc_data = (pcd_enc_data_t *)read_file_to_buffer(cmdbuffer, &enc_data_size);
			if (enc_data == NULL) {
				printf("[-] WASM App: ERROR: Failed to read %s\n", cmdbuffer);
				break;
			}
			ret = pcd_dataset_add_data(dataset_index, enc_data);
			if (ret != PCD_OK) {
				printf("[-] WASM App: ERROR: Failed to add data to dataset\n");
				builtin_free(enc_data);
				break;
			}
			printf("[+] WASM App: INFO: Added %s to dataset\n", cmdbuffer);
			data_count += 1;
			builtin_free(enc_data);
			break;
		case 'c':
			ret = pcd_dataset_check_policy(dataset_index, owner_id);
			if (ret != PCD_OK) {
				if (ret == PCD_DENINED) {
					printf("[-] WASM App: ERROR: Policy does not match\n");
				}
				else {
					printf("[-] WASM App: ERROR: Policy check failed with %d\n", ret);
				}
				break;
			}
			printf("[+] WASM App: INFO: Policy passed. You can access now\n");
			break;
		case 'p':
			process_data_and_output(dataset_index, data_count);
			break;
		case 'q':
    			printf("[+] INFO: owner_id = 0x%08X\n", (uint32_t)owner_id);
			builtin_free(owner_id);
			printf("[+] Freed owner ID\n");
			printf("[+] Exiting...\n");
			return (int)pcd_dataset_release(dataset_index);
		default:
			printf("l <data path>  : load data to dataset\n");
			printf("c              : check policy\n");
			printf("p              : process and output\n");
			printf("q              : quit\n");
			break;
		}
	}

}
