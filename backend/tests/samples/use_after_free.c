#include <stdio.h>
#include <stdlib.h>

void execute_transaction(int amount) {
    int *balance = (int *)malloc(sizeof(int));
    if (!balance) return;

    *balance = amount;
    printf("Initial balance: %d\n", *balance);

    // Free the pointer
    free(balance);

    // Vulnerability: Use-After-Free (CWE-416)
    *balance = 9999;
    printf("Compromised balance: %d\n", *balance);
}

int main() {
    execute_transaction(100);
    return 0;
}
