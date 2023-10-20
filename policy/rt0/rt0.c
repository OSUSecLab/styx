#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rt0.h"
#include "rt0_utils.h"

/////////////////////////////////////////////////
//                                             //
//   Entity Operations                         //
//                                             //
/////////////////////////////////////////////////

rt0_role_id rt0_get_role_id(rt0_entity_t *A, const char *name) {
	rt0_role_name_list_entry_t *iterator = A->role_names;
	rt0_role_id current_id = 0;
	while (iterator != NULL) {
		if (!strncmp(iterator->role_name, name, RT0_MAX_NAME)) {
			// Found
			return current_id;
		}
		else {
			current_id += 1;
			iterator = iterator->next;
		}
	}
	return -1;
}

/////////////////////////////////////////////////
//                                             //
//   rmem                                      //
//                                             //
/////////////////////////////////////////////////

rt0_utils_member_buffer_t *rt0_rmem(const rt0_role_t *role) {
	rt0_utils_member_buffer_t *ret_val = malloc(sizeof(rt0_utils_member_buffer_t));
	if (ret_val == NULL) {
		return NULL;
	}

	// TODO: Implement the discover algorithm

	return ret_val;
}

/////////////////////////////////////////////////
//                                             //
//   Role Expression                           //
//                                             //
/////////////////////////////////////////////////



rt0_utils_member_buffer_t *rt0_expr_rmem_entity(const rt0_entity_t *entity) {
	rt0_utils_member_buffer_t *ret_val = rt0_utils_alloc_empty_member_buffer();
	if (ret_val == NULL) {
		return NULL;
	}

	if (rt0_utils_member_buffer_add(entity, ret_val)) {
		rt0_utils_free_member_buffer(ret_val);
		return NULL;
	}

	return ret_val;
}

rt0_utils_member_buffer_t *rt0_expr_rmem_role(const rt0_role_t *role) {
	rt0_utils_member_buffer_t *ret_val;

	ret_val = rt0_rmem(role);

	return ret_val;
}

rt0_utils_member_buffer_t *rt0_expr_rmem_linked_role(const rt0_linked_role_t *linked_role) {
	rt0_utils_member_buffer_t *outer_members;
	rt0_utils_member_buffer_iterator_t *outer_iterator;
	rt0_utils_member_buffer_t *sub_members;
	rt0_utils_member_buffer_t *ret_val;
	rt0_role_t outer_role;
	rt0_role_t temp_role_iterator;
	int remains, i;

	ret_val = rt0_utils_alloc_empty_member_buffer();
	if (ret_val == NULL) {
		return NULL;
	}

	outer_role.A = linked_role->A;
	outer_role.r = linked_role->r1;

	outer_members = rt0_expr_rmem_role(&outer_role);
	if (outer_members) {
		return NULL;
	}
	outer_iterator = rt0_utils_member_buffer_head(outer_members);

	while (outer_iterator->current_member != NULL) {
		temp_role_iterator.A = outer_iterator->current_member;
		temp_role_iterator.r = linked_role->r2;
		sub_members = rt0_expr_rmem_role(&temp_role_iterator);
		if (sub_members) {
			// Failed. Free up everything
			rt0_utils_free_member_buffer(ret_val);
			rt0_utils_free_member_buffer(outer_members);
			return NULL;
		}
		if (rt0_utils_merge_member_buffer(ret_val, sub_members) != 0) {
			// Failed to merge. Free up everything
			rt0_utils_free_member_buffer(ret_val);
			rt0_utils_free_member_buffer(sub_members);
			rt0_utils_free_member_buffer(outer_members);
			return NULL;
		}
		rt0_utils_free_member_buffer(sub_members);
		if (rt0_utils_member_buffer_advance(outer_iterator) != 0) {
			// Failed to merge. Free up everything
			rt0_utils_free_member_buffer(ret_val);
			rt0_utils_free_member_buffer(outer_members);
			return NULL;
		}
	}

	rt0_utils_free_member_buffer(outer_members);

	return ret_val;
}

rt0_utils_member_buffer_t *rt0_expr_rmem_intersection(const rt0_intersection_t *intersection) {
	rt0_utils_member_buffer_t *ret_val;
	rt0_utils_member_buffer_t *sub_members;
	rt0_ni_re_list_entry_t *iterator;

	ret_val = rt0_utils_alloc_empty_member_buffer();
	if (ret_val == NULL) {
		return NULL;
	}

	iterator = intersection->f;

	while (iterator != NULL) {
		switch (iterator->type) {
			case RT0_RE_INVALID:
				rt0_utils_free_member_buffer(ret_val);
				return NULL;
			case RT0_RE_ENTITY:
				sub_members = rt0_expr_rmem_entity(iterator->entity);
			case RT0_RE_ROLE:
				sub_members = rt0_expr_rmem_role(&iterator->role);
			case RT0_RE_LINKED_ROLE:
				sub_members = rt0_expr_rmem_linked_role(&iterator->linked_role);
			default:
				rt0_utils_free_member_buffer(ret_val);
				return NULL;
		}

		if (sub_members == NULL) {
			rt0_utils_free_member_buffer(ret_val);
			return NULL;
		}

		if (rt0_utils_intersect_member_buffer(ret_val, sub_members) != 0) {
			rt0_utils_free_member_buffer(ret_val);
			rt0_utils_free_member_buffer(sub_members);
			return NULL;
		}

		iterator = iterator->next;
	}

	return ret_val;
}

rt0_utils_member_buffer_t *rt0_expr_rmem(const rt0_role_expression_t *role_expression) {
	switch(role_expression->type) {
		case RT0_RE_INVALID:
			return NULL;
		case RT0_RE_ENTITY:
			return rt0_expr_rmem_entity(role_expression->entity);
		case RT0_RE_ROLE:
			return rt0_expr_rmem_role(&role_expression->role);
		case RT0_RE_LINKED_ROLE:
			return rt0_expr_rmem_linked_role(&role_expression->linked_role);
		case RT0_RE_INTERSECTION:
			return rt0_expr_rmem_intersection(&role_expression->intersection);
		default:
			return NULL;
	}
}