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

#include <fcntl.h>
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
		printf("connection to %s error, %s, line %d.\n", target_path, strerror(errno), __LINE__);
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

char *read_file_to_buffer(const char *filename, size_t *ret_size) {
    char *buffer;
    int file;
    size_t file_size, buf_size, read_size;
    struct stat stat_buf;

    if (!filename || !ret_size) {
        printf("ERROR: Read file to buffer failed: invalid filename or ret size.\n");
        return NULL;
    }

    file = open(filename, O_RDONLY);
    if (file < 0) {
        printf("ERROR: Read file to buffer failed: open file %s failed.\n", filename);
        return NULL;
    }

    if (fstat(file, &stat_buf) != 0) {
        printf("ERROR: Read file to buffer failed: fstat file %s failed.\n", filename);
        close(file);
        return NULL;
    }
    file_size = stat_buf.st_size;

    /* At lease alloc 1 byte to avoid malloc failed */
    buf_size = file_size > 0 ? file_size : 1;

    if (!(buffer = (char *)malloc(buf_size))) {
        printf("ERROR: Read file to buffer failed: alloc memory failed.\n");
        close(file);
        return NULL;
    }

    read_size = read(file, buffer, file_size);
    close(file);

    if (read_size < file_size) {
        printf("ERROR: Read file to buffer failed: read file content failed.\n");
        free(buffer);
        return NULL;
    }

    *ret_size = file_size;
    return buffer;
}

char cmdbuffer[100];
char targetbuffer[100];
char outbuffer[100];

#define PCD_APP_STACK_SIZE (4 * 1024 * 1024)
#define PCD_APP_HEAP_SIZE (100 * 1024 * 1024)


char path_buffer[100];

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    int ret;
    uint32_t status;
	sgx_status_t sgx_status;
    char *module_buffer;
    size_t module_size;
    char *uuid_buffer;
    size_t uuid_size;
    int disc_count = 0;
    uint32_t app_argv[2] = {0, 0};


    char allow_dir[] = "/home/nskernel/pcd/platforms/sgx/demo/";
    char allow_dir_2[] = "/home/nskernel/pcd/platforms/sgx/demo/transformer_middleware/";
    char *static_allow_list[2] = { allow_dir,  allow_dir_2};

    printf("Allow %s\n", static_allow_list[0]);

    // Create enclave
    if (load_enclave()) {
        return -1;
    }

    // Initalise the environment
	ecall_init_env(g_consumer_enclave_id);
	pcd_sgx_attestation_register_send_receive((void *)&client_send_receive);

    printf("Enter DISC count> ");
    scanf("%d", &disc_count);

    while (disc_count--) {
        printf("Enter DISC module path> ");
        scanf("%s", path_buffer);
        module_buffer = read_file_to_buffer(path_buffer, &module_size);
        if (module_buffer == NULL) {
            printf("Failed to read module\n");
            sgx_destroy_enclave(g_consumer_enclave_id);
            return -1;
        }
        
        printf("Enter DISC UUID path> ");
        scanf("%s", path_buffer);
        uuid_buffer = read_file_to_buffer(path_buffer, &uuid_size);
        if (uuid_buffer == NULL) {
            printf("Failed to read UUID\n");
            sgx_destroy_enclave(g_consumer_enclave_id);
            return -1;
        }
        if (uuid_size != 16) {
            printf("Incorrect UUID size of %ld\n", uuid_size);
            sgx_destroy_enclave(g_consumer_enclave_id);
            return -1;
        }

        // Load
        sgx_status = ecall_load_disc(g_consumer_enclave_id, &ret, module_buffer, module_size, uuid_buffer);
        if (sgx_status != SGX_SUCCESS) {
            printf("ERROR: ecall_load_disc failed with %d\n", sgx_status);
            sgx_destroy_enclave(g_consumer_enclave_id);
            return -1;
        }
        if (ret != 0) {
            printf("ERROR: ecall_load_disc returned %d\n", ret);
            sgx_destroy_enclave(g_consumer_enclave_id);
            return -1;
        }
        //free(module_buffer);
        // Cannot fuckin free because some idiots in bytealliance
        // uses strings from the original code buffer
        free(uuid_buffer);
        printf("INFO: Loaded\n");
    }

    // Load the app
    printf("Enter app module path> ");
    scanf("%s", path_buffer);
    module_buffer = read_file_to_buffer(path_buffer, &module_size);
    if (module_buffer == NULL) {
        printf("Failed to read app module\n");
        sgx_destroy_enclave(g_consumer_enclave_id);
        return -1;
    }

    printf("Enter custodian ID UUID path> ");
    scanf("%s", path_buffer);
    uuid_buffer = read_file_to_buffer(path_buffer, &uuid_size);
    if (uuid_buffer == NULL) {
        printf("Failed to read UUID\n");
        sgx_destroy_enclave(g_consumer_enclave_id);
        return -1;
    }
    if (uuid_size != 16) {
        printf("Incorrect UUID size of %ld\n", uuid_size);
        sgx_destroy_enclave(g_consumer_enclave_id);
        return -1;
    }

    sgx_status = ecall_run_app(g_consumer_enclave_id, &ret, (uint8_t *)module_buffer, module_size, uuid_buffer, static_allow_list, 2, 
                                PCD_APP_STACK_SIZE, PCD_APP_HEAP_SIZE, (uint32_t *)app_argv, 2);
    if (sgx_status != SGX_SUCCESS) {
        printf("ERROR: ecall_run_app failed with %d\n", sgx_status);
        sgx_destroy_enclave(g_consumer_enclave_id);
        return -1;
    }
    if (ret != 0) {
        printf("ERROR: ecall_run_app returned %d\n", ret);
        sgx_destroy_enclave(g_consumer_enclave_id);
        return -1;
    }

    // We don't free anything anymore because the middleware is exiting
    // so we don't care
    printf("Exiting...\n");
    sgx_destroy_enclave(g_consumer_enclave_id);
    printf("Done\n");

    return 0;
}
