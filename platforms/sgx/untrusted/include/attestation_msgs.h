#ifndef _ATTESTATIO_MSGS_H_
#define _ATTESTATIO_MSGS_H_

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "sgx_eid.h"
#include "dcap_dh_def.h"

typedef enum {
	PCD_SGX_ATT_DH_REQ_MSG1,
	PCD_SGX_ATT_DH_RESP_MSG1,
	PCD_SGX_ATT_DH_MSG2,
	PCD_SGX_ATT_DH_MSG3,
	PCD_SGX_ATT_DH_MSG_REQ,
	PCD_SGX_ATT_DH_MSG_RESP,
	PCD_SGX_ATT_DH_CLOSE_REQ,
	PCD_SGX_ATT_DH_CLOSE_RESP
} pcd_sgx_attestation_msg_type_t;

typedef struct _pcd_sgx_attestation_msg_header {
	pcd_sgx_attestation_msg_type_t type;
	size_t size; // demonstrate FIFO message content size
	int sockfd;
} __attribute__((packed)) pcd_sgx_attestation_msg_header_t;

typedef struct _pcd_sgx_attestation_msg {
	pcd_sgx_attestation_msg_header_t header;
	unsigned char msgbuf[1];
} __attribute__((packed)) pcd_sgx_attestation_msg_t;

typedef struct _pcd_sgx_attestation_msg_session_close {
	uint32_t session_id;
} __attribute__((packed)) pcd_sgx_attestation_msg_session_close_t;

typedef struct _pcd_sgx_attestation_msg_dh_1_resp
{
	uint32_t sessionid;   // responder create a session ID and input here
	pcd_dh_dcap_msg1_t dh_msg1; // responder returns msg1
} __attribute__((packed)) pcd_sgx_attestation_msg_dh_1_resp_t;

typedef struct _pcd_sgx_attestation_msg_dh_2
{
	uint32_t sessionid;
	pcd_dh_dcap_msg2_t dh_msg2;
} __attribute__((packed)) pcd_sgx_attestation_msg_dh_2_t;

typedef struct _pcd_sgx_attestation_msg_dh_3
{
	uint32_t sessionid;
	pcd_dh_dcap_msg3_t dh_msg3;
} __attribute__((packed)) pcd_sgx_attestation_msg_dh_3_t;

typedef struct _pcd_sgx_attestation_msg_req {
	uint32_t session_id;
	size_t max_payload_size;
	size_t size;
	unsigned char buf[1];
} __attribute__((packed)) pcd_sgx_attestation_msg_req_t;

#endif
