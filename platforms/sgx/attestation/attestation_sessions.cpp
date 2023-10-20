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

#ifdef __cplusplus
extern "C" {
#endif

#include "log.h"

#ifdef __cplusplus
}
#endif

#define MAX_SESSION_COUNT  16

//number of open sessions
static uint32_t g_session_count = 0;

//Array of open session ids
static char g_session_id_tracker[MAX_SESSION_COUNT] = { 0 };

//Map between the session id and the session information associated with that particular session
static std::map<uint32_t, dh_session_t> g_session_info_map;

ATTESTATION_STATUS insert_session_info(uint32_t session_id, dh_session_t session_info) {
    g_session_info_map.insert(std::pair<uint32_t, dh_session_t>(session_id, session_info));
    return SUCCESS;
}

dh_session_t *get_session_info(uint32_t session_id) {
    std::map<uint32_t, dh_session_t>::iterator it = g_session_info_map.find(session_id);
    if(it != g_session_info_map.end()) {
        return &it->second;
    }
    else {
        return NULL;
    }
}

ATTESTATION_STATUS erase_session(uint32_t session_id) {
    std::map<uint32_t, dh_session_t>::iterator it = g_session_info_map.find(session_id);
    if(it == g_session_info_map.end()) {
        return INVALID_SESSION;
    }
    
    g_session_info_map.erase(session_id);

    return SUCCESS;
}

// Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if(!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //if the session structure is uninitialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (g_session_id_tracker[i] == 0)
        {
            *session_id = i;
	    g_session_id_tracker[i] = 1;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;
}

ATTESTATION_STATUS release_session_id(uint32_t session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if(g_session_id_tracker[session_id] == 0)
    {
        return INVALID_PARAMETER_ERROR;
    }

    g_session_id_tracker[session_id] = 0;
    return status;
}
