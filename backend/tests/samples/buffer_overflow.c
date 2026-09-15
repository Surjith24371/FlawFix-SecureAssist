#include <stdio.h>
#include <string.h>

void process_user_input(const char *user_data) {
    char local_buffer[16];
    // Vulnerability: Unbounded string copy (CWE-120)
    strcpy(local_buffer, user_data);
    printf("Processed input: %s\n", local_buffer);
}

int main() {
    const char *test_payload = "ThisIsAVeryLongStringExceedingSixteenBytes";
    process_user_input(test_payload);
    return 0;
}
