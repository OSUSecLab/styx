#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "error_codes.h"
#include "data.h"
#include "crypto/sha256.h"
#include "policy/policy_def.h"
#include "policy/policy_engine_helpers.h"

#include "policy_disc.h"

pcd_policy_t **policy_array;
uint32_t *policy_rule_count_array;
pcd_demo_policy_rule_t **rules_array;
pcd_demo_attribute_t **attributes_array;

extern int printf(const char *fmt, ...);

void pcd_policy_disc_print_hash(pcd_sha256_t *hash) {
	uint8_t *hash_ptr = (uint8_t *)hash;
	int i;
	for (i = 0; i < 32; i++) {
		printf("%02x", hash_ptr[i]);
	}
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

__attribute__((export_name("eval")))
int eval(pcd_payload_t **payload_ptr_array, uint32_t payload_amount) {
	int i = 0;
	int j, k;
	uint32_t ret_val = PCD_OK;
	uint32_t entry_total; 
	uint32_t owner_entry_total;

	pcd_payload_t *payload_ptr;
	pcd_sha256_t real_program_hash;
	pcd_identity_t output_custodian;

	if (pcd_get_program_hash(&real_program_hash)) {
		return PCD_RUNTIME_ERR;
	}

	if (pcd_get_output_custodian(&output_custodian)) {
		return PCD_RUNTIME_ERR;
	}

	policy_array = (pcd_policy_t **)malloc(sizeof(pcd_policy_t *) * payload_amount);
	policy_rule_count_array = (uint32_t *)malloc(sizeof(uint32_t) * payload_amount);
	rules_array = (pcd_demo_policy_rule_t **)malloc(sizeof(pcd_demo_policy_rule_t *) * payload_amount);
	attributes_array = (pcd_demo_attribute_t **)malloc(sizeof(pcd_demo_attribute_t *) * payload_amount);

	// First load all address into the arries
	for (i = 0; i < payload_amount; i++) {
		// Load policy-related data
		payload_ptr = payload_ptr_array[i];
		policy_array[i] = (pcd_policy_t *)(payload_ptr->payload + payload_ptr->data_size);
		policy_rule_count_array[i] = policy_array[i]->policy_size / sizeof(pcd_demo_policy_rule_t);
		rules_array[i] = (pcd_demo_policy_rule_t *)(policy_array[i]->policy_buffer);
		attributes_array[i] = (pcd_demo_attribute_t *)(payload_ptr->payload + payload_ptr->data_size + payload_ptr->policy_size + payload_ptr->tag_size);
	}

	// Next check policy
	for (i = 0; i < payload_amount; i++) {
		for (j = 0; j < policy_rule_count_array[i]; j++) {
			switch (rules_array[i][j].rule_type) {
			case PCD_DEMO_POLICY_TYPE_PROGRAM_HASH:
				if (strncmp((char *)&real_program_hash, (char *)&rules_array[i][j].program_hash, sizeof(pcd_sha256_t))) {
					printf("[-] DISC: ERROR: Program hash mismatch on data %d\n", i);
					printf("                 Real hash    :");
					pcd_policy_disc_print_hash(&real_program_hash);
					printf("\n");
					printf("                 Expected hash:");
					pcd_policy_disc_print_hash(&rules_array[i][j].program_hash);
					printf("\n");
					ret_val = PCD_DENINED;
					goto fail;
				}
				break;
			case PCD_DEMO_POLICY_TYPE_ENTRY_CAP:
				entry_total = 0;
				owner_entry_total = 0;
				for (k = 0; k < payload_amount; k++) {
					// Count total
					entry_total += attributes_array[k]->number_of_entries;
					if (!pcd_compare_identity(&attributes_array[i]->custodian_id, &attributes_array[k]->custodian_id)) {
						owner_entry_total += attributes_array[k]->number_of_entries;
					}
				}
				if ((owner_entry_total * 100 / entry_total) > rules_array[i][j].entry_cap_percentage) {
					printf("[-] DISC: ERROR: Program entry count over cap on data %d\n", i);
					printf("                 owner_entry_total = %d\n", owner_entry_total);
					printf("                 entry_total = %d\n", entry_total);
					printf("                 cap = %d\n", rules_array[i][j].entry_cap_percentage);
					ret_val = PCD_DENINED;
					goto fail;
				}
				break;
			case PCD_DEMO_POLICY_TYPE_CUSTODIAN:
				owner_entry_total = 0;
				for (k = 0; k < payload_amount; k++) {
					// Count total
					if (!pcd_compare_identity(&attributes_array[i]->custodian_id, &attributes_array[k]->custodian_id)) {
						owner_entry_total += attributes_array[k]->number_of_entries;
					}
				}
				if (owner_entry_total > rules_array[i][j].custodian_info.entry_amount) {
					if (pcd_compare_identity(&attributes_array[i]->custodian_id, &output_custodian)) {
						printf("[-] DISC: ERROR: Program output custodian unmet on data %d\n", i);
						printf("                 owner_entry_total/cap = %d/%d\n", owner_entry_total, rules_array[i][j].custodian_info.entry_amount);
						printf("                 Real output custodian    :");
						pcd_policy_disc_print_id(&output_custodian);
						printf("\n");
						printf("                 Expected output custodian:");
						pcd_policy_disc_print_id(&attributes_array[i]->custodian_id);
						printf("\n");
						ret_val = PCD_DENINED;
						goto fail;
					}
				}
				break;
			default:
				ret_val = PCD_POLICY_NSUPPORT;
				goto fail;
			}
		}
	}
fail:
	free(policy_array);
	free(policy_rule_count_array);
	free(rules_array);
	free(attributes_array);

	return ret_val;
}

void dummy() {
	return;
}
