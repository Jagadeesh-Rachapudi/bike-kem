#include <string.h>  // for memcmp and memset
#include <stdlib.h>  // for malloc, free
#include <sys/stat.h>  // for checking file size
#include "bike_defs.h"

#include "kem.h"
#include "decode.h"
#include "gf2x.h"
#include "sampling.h"
#include "sha.h"
#include <stdio.h> 
#include <inttypes.h> 
#include <stdlib.h> 
#include <string.h>
#include <stdint.h>
#include <inttypes.h> 


// Adjust these sizes based on the actual BIKE Level 5 requirements
#define PUBLIC_KEY_BYTES 4992
#define SECRET_KEY_BYTES 60000  // Adjusted size
#define CIPHERTEXT_BYTES 5184
#define SHARED_SECRET_BYTES 32

#define SUCCESS 0
#define FAILURE -1

// Helper function to check if a file is empty
int file_is_empty(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size == 0;
    }
    return 1; // Treat non-existent files as empty
}

// Robust file write with proper flushing and error checks
int robust_write(const char *filename, const void *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Unable to open %s for writing!\n", filename);
        return 0;
    }

    size_t written = fwrite(data, 1, size, file);
    if (written != size) {
        printf("Error: Failed to write full data to %s (written %zu, expected %zu)!\n", filename, written, size);
        fclose(file);
        return 0;
    }

    fflush(file);  // Ensure all data is written to disk
    fclose(file);
    return 1;
}

// Robust file read with error checks
int robust_read(const char *filename, void *data, size_t size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Unable to open %s for reading!\n", filename);
        return 0;
    }

    size_t read = fread(data, 1, size, file);
    if (read != size) {
        printf("Error: Failed to read full data from %s (read %zu, expected %zu)!\n", filename, read, size);
        fclose(file);
        return 0;
    }

    fclose(file);
    return 1;
}

int main() {
    printf("Starting custom test at BIKE Level 5...\n");

    // Allocate memory for key generation, encapsulation, and decapsulation
    uint8_t *pk = (uint8_t *)malloc(PUBLIC_KEY_BYTES);
    uint8_t *sk = (uint8_t *)malloc(SECRET_KEY_BYTES);
    uint8_t *ct = (uint8_t *)malloc(CIPHERTEXT_BYTES);
    uint8_t *ss_enc = (uint8_t *)malloc(SHARED_SECRET_BYTES);
    uint8_t *ss_dec = (uint8_t *)malloc(SHARED_SECRET_BYTES);

    // Initialize memory
    memset(pk, 0, PUBLIC_KEY_BYTES);
    memset(sk, 0, SECRET_KEY_BYTES);
    memset(ct, 0, CIPHERTEXT_BYTES);
    memset(ss_enc, 0, SHARED_SECRET_BYTES);
    memset(ss_dec, 0, SHARED_SECRET_BYTES);

    DEFER_CLEANUP(m_t m, m_cleanup); 
    DEFER_CLEANUP(m_t m_temp, m_cleanup); 

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
        printf("Memory allocation failed!\n");
        return 1;
    }

    printf("Memory allocation successful.\n");

    // Check if sk.txt and pk.txt are empty
    int sk_empty = file_is_empty("/home/jagadeesh/bike-kem/Exposed_Files/sk.txt");
    int pk_empty = file_is_empty("/home/jagadeesh/bike-kem/Exposed_Files/pk.txt");

    if (!(!sk_empty && !pk_empty)) {
        // Load keys from files
        if (!robust_read("/home/jagadeesh/bike-kem/Exposed_Files/pk.txt", pk, PUBLIC_KEY_BYTES)) {
            printf("Error loading public key from pk.txt.\n");
            goto cleanup;
        }
        if (!robust_read("/home/jagadeesh/bike-kem/Exposed_Files/sk.txt", sk, SECRET_KEY_BYTES)) {
            printf("Error loading secret key from sk.txt.\n");
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

        // Save keys to files
        if (!robust_write("/home/jagadeesh/bike-kem/Exposed_Files/pk.txt", pk, PUBLIC_KEY_BYTES)) {
            printf("Error saving public key to pk.txt.\n");
            goto cleanup;
        }
        if (!robust_write("/home/jagadeesh/bike-kem/Exposed_Files/sk.txt", sk, SECRET_KEY_BYTES)) {
            printf("Error saving secret key to sk.txt.\n");
            goto cleanup;
        }
        printf("Keys successfully saved to sk.txt and pk.txt.\n");
    }

    // Open the file 'message.txt'
    FILE *file = fopen("/home/jagadeesh/bike-kem/Exposed_Files/message.txt", "r");
    if (!file) {
        fprintf(stderr, "Error: Unable to open message.txt\n");
        return FAILURE;
    }

    // unsigned char m_raw[M_BYTES];  // Buffer to hold chunks of 32 bytes
    size_t read_count = 0;

    // Loop through the file and read data in chunks of M_BYTES
    while (1) {
        // Clear the buffer for every new chunk

        // Read up to M_BYTES values from the file
        for (read_count = 0; read_count < M_BYTES; read_count++) {
            m_temp.raw[read_count]=0;
            if (fscanf(file, "%hhu", &m_temp.raw[read_count]) != 1) {
                break;  // Stop reading if we reach EOF or encounter an error
            }
        }

        // If no more data was read, break the loop
        if (read_count == 0) {
            break;
        }

        // If we read less than M_BYTES, padding has already been done with '0's by memset
        // Proceed with encryption using m_raw as the input data (of size M_BYTES)
        // Note: You will need to adapt m_raw to work with the m structure used in your encapsulation call

        // Create a temporary structure `m` that uses `m_raw` and call the encapsulation function
        // struct { unsigned char raw[M_BYTES]; } m;
        memcpy(m.raw, m_temp.raw, M_BYTES);  // Copy the buffer to m.raw

        // Encapsulation
        if (crypto_kem_enc(ct, ss_enc, pk, m) != 0) {
            printf("Encapsulation failed!\n");
            fclose(file);
            return FAILURE;
        }

        // Break if the last chunk read was less than M_BYTES, indicating EOF
        if (read_count < M_BYTES) {
            break;
        }
    }

    // Close the file
    fclose(file);


    printf("Encapsulation successful.\n");

    // Save ciphertext to file
    if (!robust_write("/home/jagadeesh/bike-kem/Exposed_Files/cipher.txt", ct, CIPHERTEXT_BYTES)) {
        printf("Error saving ciphertext to cipher.txt.\n");
        goto cleanup;
    }

    printf("Ciphertext successfully written to cipher.txt.\n");

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
    // if (pk) free(pk);
    // if (sk) free(sk);
    // if (ct) free(ct);
    // if (ss_enc) free(ss_enc);
    // if (ss_dec) free(ss_dec);

    return 0;
}
