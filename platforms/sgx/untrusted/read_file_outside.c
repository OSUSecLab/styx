#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void ocall_read_file_to_outside_buffer(char **ret_buffer, int file, size_t file_size, size_t *read_size) {
	char *buffer;
	size_t read_size_real;
	
	buffer = malloc(file_size);
	if (buffer == NULL) {
		*ret_buffer = NULL;
	}
	*ret_buffer = buffer;

	read_size_real = read(file, buffer, file_size);
	*read_size = read_size_real;

	*ret_buffer = buffer;
}

void ocall_free_outside_buffer(char *outside_buffer) {
	free(outside_buffer);
}