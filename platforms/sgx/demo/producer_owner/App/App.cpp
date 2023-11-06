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
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

extern "C" void ocall_print(const char* str) {
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
        printf("Producer Owner App: Failed to load enclave %s. Error code is 0x%x.\n", GATEWAY_ENCLAVE_NAME, ret);
        return -1;
    }

    return 0;
}

#define BUFFER_SIZE 8192

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
char outbuffer[100];

typedef uint8_t sha256_t[32]; 
typedef uint8_t uuid_t[16]; 

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    int target_id;
    size_t out_len;
    int ret;
    uint32_t status;
    int if_continue = 1;
    FILE *fp = NULL;
    long fsize;
    char *filebuffer;
    char *output_data;
    size_t data_size;
    uint64_t number_count;
    uint64_t *input_buffer;
    void *input_file_buffer;
    size_t input_size;
    int i;
    uint8_t rule_mask;

    char *uuid_path;
    char *hash_path;

    uint8_t *owner_id;
    uint8_t *program_hash;
    size_t read_buffer_size;

    if (argc != 3) {
	    printf("usage: producer_owner <uuid path> <hash path>\n");
		return -1;
    }

    uuid_path = argv[1];
    hash_path = argv[2];

    owner_id = (uint8_t *)read_file_to_buffer(uuid_path, &read_buffer_size);
    if (owner_id == NULL) {
        printf("ERROR: Failed to read owner UUID\n");
        return -1;
    }
    if (read_buffer_size != sizeof(uuid_t)) {
        printf("ERROR: UUID size incorrect! read_buffer_size = %ld\n", read_buffer_size);
        return -1;
    }

    program_hash = (uint8_t *)read_file_to_buffer(hash_path, &read_buffer_size);
    if (program_hash == NULL) {
        printf("ERROR: Failed to read prgram hash\n");
        return -1;
    }
    if (read_buffer_size != sizeof(sha256_t)) {
        printf("ERROR: Hash size incorrect! read_buffer_size = %ld\n", read_buffer_size);
        return -1;
    }


    // Create enclave
    if (load_enclave()) {
        return -1;
    }

    // Initalise the environment
	ecall_init_env(g_consumer_enclave_id, owner_id, program_hash);
    free(owner_id);
    free(program_hash);

	pcd_sgx_attestation_register_send_receive((void *)&client_send_receive);

    output_data = (char *)malloc(8192);
    if (output_data == NULL) {
        printf("ERROR: Failed to malloc output_data\n");
        if_continue = false;
    }

    while (if_continue) {
        printf("Enter command: ");
        scanf("%s", cmdbuffer);
        if (cmdbuffer[1] != 0) {
            printf("Error: Unknown command\n");
            continue;
        }

        switch (cmdbuffer[0]) {
        case 'h':
            printf("h:                                              help\n");
            printf("o <uuid path>:                                  load new owner uuid\n");
            printf("h <hash path>:                                  load new target program hash\n");
            printf("g <num count> <nums> <rule mask> <output path>: generate data\n");
            printf("a <input path> <rule mask> <output path>:       pack data\n");
            printf("p:                                              push secret to remote\n");
            printf("q:                                              quit\n");
            break;
        case 'o':
            scanf("%s", cmdbuffer);
            owner_id = (uint8_t *)read_file_to_buffer(cmdbuffer, &read_buffer_size);
            if (owner_id == NULL) {
                printf("ERROR: Failed to read owner UUID\n");
                continue;
            }
            if (read_buffer_size != sizeof(uuid_t)) {
                printf("ERROR: UUID size incorrect! read_buffer_size = %ld\n", read_buffer_size);
                free(owner_id);
                continue;
            }
            ecall_change_owner_id(g_consumer_enclave_id, owner_id);
            free(owner_id);
            break;
        case 't':
            scanf("%s", cmdbuffer);
            program_hash = (uint8_t *)read_file_to_buffer(cmdbuffer, &read_buffer_size);
            if (program_hash == NULL) {
                printf("ERROR: Failed to read prgram hash\n");
                continue;
            }
            if (read_buffer_size != sizeof(sha256_t)) {
                printf("ERROR: Hash size incorrect! read_buffer_size = %ld\n", read_buffer_size);
                continue;
            }
            ecall_change_target_hash(g_consumer_enclave_id, program_hash);
            free(program_hash);
            break;
        case 'p':
            ecall_push_secret_to_remote(g_consumer_enclave_id, &ret);
			if (ret != 0) {
				printf("ERROR: push to remote failed with %d\n", ret);
			}
            break;
        case 'g':
            scanf("%ld", &number_count);
            input_buffer = (uint64_t *)malloc(sizeof(uint64_t) * number_count);
            for (i = 0; i < number_count; i++) {
                scanf("%ld", &input_buffer[i]);
            }
            scanf("%hhd %s", &rule_mask, cmdbuffer);

            // Produce
            if ((status = ecall_produce_data(g_consumer_enclave_id, (int *)&ret, input_buffer, number_count, output_data, &data_size, 8192, rule_mask)) != SGX_SUCCESS) {
				printf("ERROR: ecall_produce_data failed with %d\n", status);
                if_continue = false;
                free(input_buffer);
                continue;
			}
            free(input_buffer);
            printf("INFO: ecall_produce_data returned %d\n", ret);
            if (ret != 0) {
                printf("ERROR: ecall_produce_data failed to produce data\n");
                if_continue = false;
                continue;
            }

            // Open file
            fp = fopen(cmdbuffer, "w+");
            if (fp == NULL) {
                printf("Error: Failed to open file %s\n", cmdbuffer);
                continue;
            }
            fwrite(output_data, data_size, 1, fp);
            fclose(fp);
            
            break;
        case 'a':
            scanf("%s", cmdbuffer);
            input_file_buffer = (void *)read_file_to_buffer(cmdbuffer, &input_size);
            scanf("%hhd %s", &rule_mask, cmdbuffer);

            if (input_file_buffer == NULL) {
                printf("ERROR: Failed to read file/create file buffer\n");
                continue;
            }

            // Rebuild the output buffer
            free(output_data);
            output_data = (char *)malloc(input_size + 8196);
            if (output_data == NULL) {
                printf("ERROR: Failed to reallocate output buffer\n");
                if_continue = false;
                free(input_file_buffer);
                continue;
            }
            printf("INFO: output_data's max size is set to %d\n", input_size + 8196);

            // Produce
            if ((status = ecall_pack_data(g_consumer_enclave_id, (int *)&ret, input_file_buffer, input_size, output_data, &data_size, input_size + 8196, rule_mask)) != SGX_SUCCESS) {
				printf("ERROR: ecall_pack_data failed with %d\n", status);
                if_continue = false;
                free(input_file_buffer);
                continue;
			}
            free(input_file_buffer);
            printf("INFO: ecall_pack_data returned %d\n", ret);
            if (ret != 0) {
                printf("ERROR: ecall_pack_data failed to produce data\n");
                if_continue = false;
                continue;
            }

            // Open file
            fp = fopen(cmdbuffer, "w+");
            if (fp == NULL) {
                printf("Error: Failed to open file %s\n", cmdbuffer);
                continue;
            }
            fwrite(output_data, data_size, 1, fp);
            fclose(fp);
            
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
