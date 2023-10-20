/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <map>
#include <sys/stat.h>
#include <sched.h>

#include "Enclave_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#include "cpdef.h"

#include "CPTask.h"
#include "CPServer.h"

extern "C" {

#include "attestation_msgs.h"
#include "attestation/prover_untrusted.h"

}

sgx_enclave_id_t e2_enclave_id = 0;

#define PROVER_ENCLAVE_NAME "enclave.signed.so"

/* Function Description: load prover enclave
 * */
int load_enclaves()
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int update = 0;

    ret = sgx_create_enclave(PROVER_ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &update, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) 
    {
        printf("failed to load enclave %s, error code is 0x%x.\n", PROVER_ENCLAVE_NAME, ret);
        return -1;
    }

    return 0;
}

void CPTask::run()
{
    pcd_sgx_attestation_msg_t * message = NULL;
    pcd_sgx_attestation_msg_t * resp_message = NULL;
    size_t resp_size;
    sgx_launch_token_t token = {0};
    int status;
    int update = 0;
    int clientfd;

    // load prover enclave 
    status = sgx_create_enclave(PROVER_ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &update, &e2_enclave_id, NULL);
    if (status != SGX_SUCCESS)
    {
        printf("failed to load enclave %s, error code is 0x%x.\n", PROVER_ENCLAVE_NAME, status);
        return;
    }

    while (!isStopped())
    {
        /* receive task frome queue */
        message  = m_queue.blockingPop();
        if (isStopped())
        {
            free(message);
            break;
        }
		printf("Received message...\n");
        clientfd = message->header.sockfd;

        status = pcd_sgx_attestation_prover_process_msg(e2_enclave_id, message, &resp_message, &resp_size);
		if (status != 0) {
			printf("ERROR: pcd_sgx_attestation_prover_process_msg returned %d\n", status);
		}
		printf("Processed message.\n");

        if (send(clientfd, reinterpret_cast<char *>(resp_message), resp_size, 0) == -1)
        {
            printf("server_send() failure.\n");
        }

        free(message);
        free(resp_message);
        message = NULL;
        resp_message = NULL;
    }

    sgx_destroy_enclave(e2_enclave_id);
}

void CPTask::shutdown()
{
    stop();
    m_queue.close();
    join();
}

void CPTask::puttask(pcd_sgx_attestation_msg_t* requestData)
{
    if (isStopped()) {
        return;
    }
    
    m_queue.push(requestData);
}

