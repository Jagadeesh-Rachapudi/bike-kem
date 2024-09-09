#include <stdio.h>
#include <string.h>  // for memcmp
#include <stdlib.h>  // for malloc, free
#include "kem.h"     // Include necessary headers from BIKE

// Adjust these sizes based on the actual BIKE Level 5 requirements
#define PUBLIC_KEY_BYTES 4992
#define SECRET_KEY_BYTES 100000  // Increased to avoid overflow
#define CIPHERTEXT_BYTES 5184
#define SHARED_SECRET_BYTES 32

int main() {
    printf("Starting custom test at BIKE Level 5...\n");

    // Allocate memory for key generation, encapsulation, and decapsulation
    uint8_t *pk = (uint8_t *)malloc(PUBLIC_KEY_BYTES);
    uint8_t *sk = (uint8_t *)malloc(SECRET_KEY_BYTES);
    uint8_t *ct = (uint8_t *)malloc(CIPHERTEXT_BYTES);
    uint8_t *ss_enc = (uint8_t *)malloc(SHARED_SECRET_BYTES);
    uint8_t *ss_dec = (uint8_t *)malloc(SHARED_SECRET_BYTES);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
        printf("Memory allocation failed!\n");
        return 1;
    }

    printf("Memory allocation successful.\n");

    // Generate a key pair
    if (crypto_kem_keypair(pk, sk) != 0) {
        printf("Key generation failed!\n");
        goto cleanup;
    }

    printf("Key generation successful.\n");

    // Encapsulation
    if (crypto_kem_enc(ct, ss_enc, pk) != 0) {
        printf("Encapsulation failed!\n");
        goto cleanup;
    }

    printf("Encapsulation successful.\n");

    // Decapsulation
    if (crypto_kem_dec(ss_dec, ct, sk) != 0) {
        printf("Decapsulation failed!\n");
        goto cleanup;
    }

    printf("Decapsulation successful.\n");

    
    // Verify that the encapsulated and decapsulated shared secrets are the same
    if (memcmp(ss_enc, ss_dec, SHARED_SECRET_BYTES) == 0) {
        printf("Success! Decapsulated key matches encapsulated key.\n");
    } else {
        printf("Failure! Keys do not match.\n");
    }

cleanup:
    // Free allocated memory
    if (pk) free(pk);
    if (sk) free(sk);
    if (ct) free(ct);
    if (ss_enc) free(ss_enc);
    if (ss_dec) free(ss_dec);

    return 0;
}
