#include <stdint.h>

#ifndef RT0_H__
#define RT0_H__

#define RT0_MAX_NAME	128

typedef struct {

} rt0_public_key_t;


// Role name -> role ID for each entity
typedef struct rt0_role_name_list_entry {
	char role_name[RT0_MAX_NAME];
	struct rt0_role_name_list_entry *next;
} rt0_role_name_list_entry_t;

typedef int rt0_role_id;

// Entity must be referenced by pointer!
typedef struct {
	char name[RT0_MAX_NAME];
	rt0_public_key_t public_key;
	rt0_role_name_list_entry_t *role_names;
} rt0_entity_t;


/////////////////////////////////////////////////
//                                             //
//   Role Expression                           //
//                                             //
/////////////////////////////////////////////////

#define RT0_RE_INVALID		-1
#define RT0_RE_ENTITY		0
#define RT0_RE_ROLE		1
#define RT0_RE_LINKED_ROLE	2
#define RT0_RE_INTERSECTION	3

// Role: A.r
typedef struct {
	rt0_entity_t *A;
	rt0_role_id r;
} rt0_role_t;

// Linked Role: A.r1.r2
typedef struct {
	rt0_entity_t *A;
	rt0_role_id r1;
	rt0_role_id r2;
} rt0_linked_role_t;

// Non-Intersection
typedef struct rt0_ni_re_list_entry {
	int type;
	union {
		rt0_entity_t *entity;
		rt0_role_t role;
		rt0_linked_role_t linked_role;
	};
	struct rt0_ni_re_list_entry *next;
} rt0_ni_re_list_entry_t;

// Intersection: \Cap_{i=1}^{k}f_i
// f_i is non-intersection and must start with A
typedef struct {
	int k;
	rt0_entity_t *A;
	rt0_ni_re_list_entry_t *f;
} rt0_intersection_t;

typedef struct {
	int type;
	union {
		rt0_entity_t *entity;
		rt0_role_t role;
		rt0_linked_role_t linked_role;
		rt0_intersection_t intersection;
	};
} rt0_role_expression_t;


/////////////////////////////////////////////////
//                                             //
//   Credentials                               //
//                                             //
/////////////////////////////////////////////////

// Type-1: A.r <- B
typedef struct {
	rt0_role_t left;
	rt0_entity_t *B;
} rt0_type_1_cred_t;

// Type-2: A.r <- B.r1
typedef struct {
	rt0_role_t left;
	rt0_role_t right;
} rt0_type_2_cred_t;

// Type-3: A.r <- A.r1.r2
// Note left and right must have the same entity!
typedef struct {
	rt0_role_t left;
	rt0_linked_role_t right;
} rt0_type_3_cred_t;

// Type-4: A.r <- f_1 \cap \cdots \cap f_n
typedef struct {
	rt0_role_t left;
	rt0_intersection_t right;
} rt0_type_4_cred_t;

typedef struct {
	int type;
	union {
		rt0_type_1_cred_t type_1_cred;
		rt0_type_2_cred_t type_2_cred;
		rt0_type_3_cred_t type_3_cred;
		rt0_type_4_cred_t type_4_cred;
	};
} rt0_cred_t;


#endif