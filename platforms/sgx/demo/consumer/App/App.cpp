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
#include <sched.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "sgx_eid.h"

#include "Enclave_u.h"

extern "C" {

#include "attestation/challenger_untrusted.h"

}

#include <limits.h>

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include <stdint.h>

#define GATEWAY_ENCLAVE_NAME "enclave.signed.so"

sgx_enclave_id_t g_consumer_enclave_id = -1;

void ocall_print(const char* str) {
	printf("%s", str);
}

int load_enclave()
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int update = 0;

    ret = sgx_create_enclave(GATEWAY_ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &update, &g_consumer_enclave_id, NULL);
    if (ret != SGX_SUCCESS) 
    {
        printf("Consumer App: Failed to load enclave %s. Error code is 0x%x.\n", GATEWAY_ENCLAVE_NAME, ret);
        return -1;
    }

    return 0;
}

#define BUFFER_SIZE 8192

extern "C" {
#include "attestation_msgs.h"
}

static int client_send_receive(char *req_msg, size_t req_size, char **resp_msg, size_t *resp_size, char *target_path)
{
    int ret = 0;
    long byte_num;
    char recv_msg[BUFFER_SIZE + 1] = {0};
    char * response = NULL;
  
    struct sockaddr_un server_addr;
    int server_sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (server_sock_fd == -1)
    {
        printf("socket error");
        return -1;
    }

	printf("INFO: req_msg type is %d\n", ((pcd_sgx_attestation_msg_t*)req_msg)->header.type);

    server_addr.sun_family = AF_UNIX;
    
    strcpy(server_addr.sun_path, target_path);


    if (connect(server_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("connection error, %s, line %d.\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    if ((byte_num = send(server_sock_fd, reinterpret_cast<char *>(req_msg), static_cast<int>(req_size), 0)) == -1)
    {
        printf("connection error, %s, line %d..\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    byte_num = recv(server_sock_fd, reinterpret_cast<char *>(recv_msg), BUFFER_SIZE, 0);
    if (byte_num > 0)
    {
        if (byte_num > BUFFER_SIZE)
        {
            byte_num = BUFFER_SIZE;
        }

        recv_msg[byte_num] = '\0';

        response = (char *)malloc((size_t)byte_num);
        if (!response)
        {
            printf("memory allocation failure.\n");
            ret = -1;
            goto CLEAN;
        }
        memset(response, 0, (size_t)byte_num);

        memcpy(response, recv_msg, (size_t)byte_num);

        *resp_msg = response;
        *resp_size = (size_t)byte_num;

        ret = 0;
    }
    else if(byte_num < 0)
    {
        printf("server error, error message is %s!\n", strerror(errno));
        ret = -1;
    }
    else
    {
        printf("server exit!\n");
        ret = -1;
    }


CLEAN:
    close(server_sock_fd);

    return ret;
}


char cmdbuffer[100];
char outbuffer[100];
char username[100];
char password[100];

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    int target_id;
    size_t out_len;
    int ret;
    uint32_t status;
	sgx_status_t sgx_status;
    int if_continue = 1;
    FILE *fp = NULL;
    long fsize;
    char *filebuffer;
    char *output_data;
    size_t data_size;

    // Create enclave
    if (load_enclave()) {
        return -1;
    }

    // Initalise the environment
	ecall_init_env(g_consumer_enclave_id);
	pcd_sgx_attestation_register_send_receive((void *)&client_send_receive);

    // Login
    while (1) {
        printf("Consumer login: ");
        scanf("%s", username);
        printf("Password: ");
        scanf("%s", password);
        username[99] = 0;
        password[99] = 0;
        if (ecall_login(g_consumer_enclave_id, &status, username, password)) {
            printf("ERROR: Failed to do ecall\n");
			return -1;
        }
		if (status != 0) {
			continue;
		}
		break;
    }

    while (if_continue) {
        printf("Enter command: ");
        scanf("%s", cmdbuffer);
        if (cmdbuffer[1] != 0) {
            printf("Error: Unknown command\n");
            continue;
        }

        switch (cmdbuffer[0]) {
        case 'r':
            scanf("%s", cmdbuffer);
            // Open file
            fp = fopen(cmdbuffer, "r");
            if (fp == NULL) {
                printf("Error: PCD %s doesn't exist\n", cmdbuffer);
                continue;
            }
            fseek(fp, 0, SEEK_END);
            fsize = ftell(fp);
            fseek(fp, 0, SEEK_SET);  /* same as rewind(f); */

            filebuffer = (char *)malloc(fsize + 1);
            fread(filebuffer, fsize, 1, fp);
            fclose(fp);

            // Access
            if ((sgx_status = ecall_extract_and_print_data(g_consumer_enclave_id, (uint32_t *)&ret, filebuffer)) != SGX_SUCCESS) {
				printf("ERROR: ecall_extract_data failed %d\n", sgx_status);
			}
            printf("INFO: pcd_consumer_extract_data returned %d\n", ret);
            if (ret != 0) {
                printf("ERROR: pcd_consumer_extract_data failed to extract data\n");
            }
            break;
        case 'q':
            if_continue = false;
            break;
        default:
            printf("Error: Unknown command\n");
        }
    }

    printf("Exiting...\n");
    sgx_destroy_enclave(g_consumer_enclave_id);
    printf("Done\n");

    return 0;
}
