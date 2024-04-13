extern int ocall_print(const char *string);

void pcd_print(const char *string) {
	ocall_print(string);
}

void pcd_print_error(const char *string) {
	ocall_print(string);
}