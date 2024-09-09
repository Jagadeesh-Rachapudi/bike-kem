#include <stdio.h>
#include <string.h>  // for memcmp and memset
#include <stdlib.h>  // for malloc, free
#include <sys/stat.h>  // for checking file size
#include "kem.h"      // Include necessary headers from BIKE

// Adjust these sizes based on the actual BIKE Level 5 requirements
#define PUBLIC_KEY_BYTES 4992
#define SECRET_KEY_BYTES 60000  // Adjusted size
#define CIPHERTEXT_BYTES 5184
#define SHARED_SECRET_BYTES 32

// Helper function to check if a file is empty
int file_is_empty(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size == 0;
    }
    return 1; // Treat non-existent files as empty
}

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

    // Check if sk.txt and pk.txt are empty
    FILE *sk_file = fopen("/home/jagadeesh/bike-kem/Exposed_Files/sk.txt", "rb");
    FILE *pk_file = fopen("/home/jagadeesh/bike-kem/Exposed_Files/pk.txt", "rb");

    int sk_empty = file_is_empty("/home/jagadeesh/bike-kem/Exposed_Files/sk.txt");
    int pk_empty = file_is_empty("/home/jagadeesh/bike-kem/Exposed_Files/pk.txt");

    if (sk_file && pk_file && !sk_empty && !pk_empty) {
        // Load keys from files and check for fread return value
        if (fread(pk, 1, PUBLIC_KEY_BYTES, pk_file) != PUBLIC_KEY_BYTES) {
            printf("Error: Failed to read full public key from pk.txt!\n");
            fclose(pk_file);
            goto cleanup;
        }
        if (fread(sk, 1, SECRET_KEY_BYTES, sk_file) != SECRET_KEY_BYTES) {
            printf("Error: Failed to read full secret key from sk.txt!\n");
            fclose(sk_file);
            goto cleanup;
        }

        printf("Keys loaded from sk.txt and pk.txt.\n");
    } else {
        // Generate a new key pair
        if (crypto_kem_keypair(pk, sk) != 0) {
            printf("Key generation failed!\n");
            goto cleanup;
        }

        printf("Key generation successful.\n");

        // Save public key to pk.txt
        FILE *pk_write_file = fopen("/home/jagadeesh/bike-kem/Exposed_Files/pk.txt", "wb");
        if (!pk_write_file) {
            printf("Error: Unable to open pk.txt for writing!\n");
            goto cleanup;
        }
        if (fwrite(pk, 1, PUBLIC_KEY_BYTES, pk_write_file) != PUBLIC_KEY_BYTES) {
            printf("Error: Failed to write full public key to pk.txt!\n");
            fclose(pk_write_file);
            goto cleanup;
        }
        fclose(pk_write_file);
        printf("Public key successfully written to pk.txt.\n");

        // Save secret key to sk.txt
        FILE *sk_write_file = fopen("/home/jagadeesh/bike-kem/Exposed_Files/sk.txt", "wb");
        if (!sk_write_file) {
            printf("Error: Unable to open sk.txt for writing!\n");
            goto cleanup;
        }
        if (fwrite(sk, 1, SECRET_KEY_BYTES, sk_write_file) != SECRET_KEY_BYTES) {
            printf("Error: Failed to write full secret key to sk.txt!\n");
            fclose(sk_write_file);
            goto cleanup;
        }
        fclose(sk_write_file);
        printf("Secret key successfully written to sk.txt.\n");
    }

    fclose(sk_file);
    fclose(pk_file);

    // Encapsulation
    if (crypto_kem_enc(ct, ss_enc, pk) != 0) {
        printf("Encapsulation failed!\n");
        goto cleanup;
    }

    printf("Encapsulation successful.\n");

    // Save ciphertext to file
    FILE *cipher_file = fopen("/home/jagadeesh/bike-kem/Exposed_Files/cipher.txt", "wb");
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
    // if (pk) free(pk);
    // if (sk) free(sk);
    // if (ct) free(ct);
    // if (ss_enc) free(ss_enc);
    // if (ss_dec) free(ss_dec);

    return 0;
}
