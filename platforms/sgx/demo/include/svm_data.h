#ifndef _SVM_DATA_H_
#define _SVM_DATA_H_

#include <stdint.h>

typedef struct {
	uint64_t record_count;
	uint64_t feature_vector_length;
	double numbers[];
} __attribute__((packed)) svm_data_t;

#endif
