#include <stdio.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "attestation/attestation_errors.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "dh_session_protocol.h"

#include "sgx_tcrypto.h"
#include "dcap_dh_def.h"
#include "dcap_dh.h"
#include "dh_session_datatypes.h"

#ifndef _ATTESTATION_SESSIONS_H_
#define _ATTESTATION_SESSIONS_H_

ATTESTATION_STATUS insert_session_info(uint32_t session_id, dh_session_t session_info);
dh_session_t *get_session_info(uint32_t session_id);
ATTESTATION_STATUS erase_session(uint32_t session_id);
ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
ATTESTATION_STATUS release_session_id(uint32_t session_id);

#endif
