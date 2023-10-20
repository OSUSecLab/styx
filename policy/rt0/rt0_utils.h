#include <stdint.h>

#include "rt0.h"

#ifndef RT0_UTILS_H__
#define RT0_UTILS_H__

#define RT0_UTILS_MEMBER_BUFFER_SIZE	128

typedef struct rt0_utils_member_buffer {
	int member_count;

	// Private
	rt0_entity_t *_members[128];
	struct rt0_utils_member_buffer *_next;
} rt0_utils_member_buffer_t;

typedef struct rt0_utils_member_buffer_iterator {
	rt0_entity_t *current_member;
	rt0_utils_member_buffer_t *buffer;
} rt0_utils_member_buffer_iterator_t;

rt0_utils_member_buffer_t *rt0_utils_alloc_empty_member_buffer();
void rt0_utils_free_member_buffer(rt0_utils_member_buffer_t *buffer);
rt0_utils_member_buffer_iterator_t *rt0_utils_member_buffer_head(rt0_utils_member_buffer_t *buffer);
int rt0_utils_member_buffer_advance(rt0_utils_member_buffer_iterator_t *previous);
int rt0_utils_member_buffer_add(rt0_entity_t *entity, rt0_utils_member_buffer_t *buffer);
int rt0_utils_merge_member_buffer(rt0_utils_member_buffer_t *buffer_main, rt0_utils_member_buffer_t *buffer_sub);
int rt0_utils_intersect_member_buffer(rt0_utils_member_buffer_t *buffer_main, rt0_utils_member_buffer_t *buffer_sub);

#endif