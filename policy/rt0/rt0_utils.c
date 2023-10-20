#include <stdlib.h>
#include <stdio.h>

#include "rt0_utils.h"

rt0_utils_member_buffer_t *rt0_utils_alloc_empty_member_buffer() {
	return NULL;
}

void rt0_utils_free_member_buffer(rt0_utils_member_buffer_t *buffer) {
	// TODO
}

rt0_utils_member_buffer_iterator_t *rt0_utils_member_buffer_head(rt0_utils_member_buffer_t *buffer) {
	// TODO
	return NULL;
}

int rt0_utils_member_buffer_advance(rt0_utils_member_buffer_iterator_t *previous) {
	// TODO
	return NULL;
}

int rt0_utils_member_buffer_add(rt0_entity_t *entity, rt0_utils_member_buffer_t *buffer) {
	// TODO
	return -1;
}

// Must free the sub
int rt0_utils_merge_member_buffer(rt0_utils_member_buffer_t *buffer_main, rt0_utils_member_buffer_t *buffer_sub) {
	//TODO
	
	return -1;
}

// Must free the sub
int rt0_utils_intersect_member_buffer(rt0_utils_member_buffer_t *buffer_main, rt0_utils_member_buffer_t *buffer_sub) {
	//TODO
	
	return -1;
}