#include <stdio.h>
#include <string.h>  // for memcmp and memset
#include <stdlib.h>  // for malloc, free
#include "kem.h"     // Include necessary headers from BIKE

// Adjust these sizes based on the actual BIKE Level 5 requirements
#define PUBLIC_KEY_BYTES 4992
#define SECRET_KEY_BYTES 60000  // Adjusted size
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

    // Add memset to initialize buffers to zero
    memset(pk, 0, PUBLIC_KEY_BYTES);
    memset(sk, 0, SECRET_KEY_BYTES);
    memset(ct, 0, CIPHERTEXT_BYTES);
    memset(ss_enc, 0, SHARED_SECRET_BYTES);
    memset(ss_dec, 0, SHARED_SECRET_BYTES);

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

    // Save ciphertext to file
    FILE *cipher_file = fopen("cipher.txt", "wb");
    if (!cipher_file) {
        printf("Error: Unable to open cipher.txt for writing!\n");
        goto cleanup;
    }

    size_t written = fwrite(ct, 1, CIPHERTEXT_BYTES, cipher_file);
    if (written != CIPHERTEXT_BYTES) {
        printf("Error: Failed to write full ciphertext to cipher.txt!\n");
        fclose(cipher_file);
        goto cleanup;
    }

    printf("Ciphertext successfully written to cipher.txt.\n");
    fclose(cipher_file);

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
    // Free allocated memory with checks
    // if (pk) { free(pk); pk = NULL; }
    // if (sk) { free(sk); sk = NULL; }
    // if (ct) { free(ct); ct = NULL; }
    // if (ss_enc) { free(ss_enc); ss_enc = NULL; }
    // if (ss_dec) { free(ss_dec); ss_dec = NULL; }

    return 0;
}
