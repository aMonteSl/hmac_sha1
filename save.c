#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define SHA1_BLOCK_SIZE 64    // Size of SHA-1 block in bytes
#define SHA1_DIGEST_SIZE 20   // Size of SHA-1 hash in bytes

void print_key_length_warning(size_t key_len);
void fill_key_with_zeros(unsigned char *key_buffer, size_t key_len);
void xor_with_ipad_or_opad(unsigned char *key_buffer, unsigned char *result, unsigned char xor_value);
void initialize_hash_context(EVP_MD_CTX *ctx);
void read_key(FILE *key, unsigned char *key_buffer, size_t *key_len);
void process_data(FILE *data, EVP_MD_CTX *ctx);
void finalize_hash(EVP_MD_CTX *ctx, unsigned char *partial, unsigned char *key_buffer, unsigned char *final);
void print_final_result(unsigned char *final, unsigned int final_len);

void print_key_length_warning(size_t key_len) {
    if (key_len < SHA1_DIGEST_SIZE) {
        fprintf(stderr, "Warning: the key is too short (should be longer than %d bytes)\n", SHA1_DIGEST_SIZE);
    }
}

void fill_key_with_zeros(unsigned char *key_buffer, size_t key_len) {
    if (key_len < SHA1_BLOCK_SIZE) {
        memset(key_buffer + key_len, 0, SHA1_BLOCK_SIZE - key_len);
    }
}

void xor_with_ipad_or_opad(unsigned char *key_buffer, unsigned char *result, unsigned char xor_value) {
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        result[i] = key_buffer[i] ^ xor_value;
    }
}

void initialize_hash_context(EVP_MD_CTX *ctx) {
    if (EVP_DigestInit(ctx, EVP_sha1()) != 1) {
        fprintf(stderr, "Error initializing hash\n");
        exit(EXIT_FAILURE);
    }
}

void read_key(FILE *key, unsigned char *key_buffer, size_t *key_len) {
    *key_len = fread(key_buffer, 1, SHA1_BLOCK_SIZE, key);

    if (ferror(key)) {
        fprintf(stderr, "Error reading key\n");
        exit(EXIT_FAILURE);
    }
}

void process_data(FILE *data, EVP_MD_CTX *ctx) {
    unsigned char data_buffer[1024];
    size_t data_len;

    while ((data_len = fread(data_buffer, 1, 1024, data)) > 0) {
        if (EVP_DigestUpdate(ctx, data_buffer, data_len) != 1) {
            fprintf(stderr, "Error updating hash with data\n");
            exit(EXIT_FAILURE);
        }
    }

    if (ferror(data)) {
        fprintf(stderr, "Error reading data\n");
        exit(EXIT_FAILURE);
    }
}

void finalize_hash(EVP_MD_CTX *ctx, unsigned char *partial, unsigned char *key_buffer, unsigned char *final) {
    unsigned int partial_len;

    if (EVP_DigestFinal_ex(ctx, partial, &partial_len) != 1) {
        fprintf(stderr, "Error finalizing hash\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit(ctx, EVP_sha1()) != 1) {
        fprintf(stderr, "Error reinitializing hash\n");
        exit(EXIT_FAILURE);
    }

    unsigned char k_opad[SHA1_BLOCK_SIZE];
    xor_with_ipad_or_opad(key_buffer, k_opad, 0x5c);

    if (EVP_DigestUpdate(ctx, k_opad, SHA1_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error updating hash with K XOR opad\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, partial, partial_len) != 1) {
        fprintf(stderr, "Error updating hash with partial result\n");
        exit(EXIT_FAILURE);
    }

    unsigned int final_len;

    if (EVP_DigestFinal_ex(ctx, final, &final_len) != 1) {
        fprintf(stderr, "Error finalizing hash\n");
        exit(EXIT_FAILURE);
    }
}

void print_final_result(unsigned char *final, unsigned int final_len) {
    for (int i = 0; i < final_len; i++) {
        printf("%02x", final[i]);
    }

    printf("\n");
}

void compute_hmac_sha1(FILE *data, FILE *key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        fprintf(stderr, "Error creating context\n");
        exit(EXIT_FAILURE);
    }

    initialize_hash_context(ctx);

    unsigned char key_buffer[SHA1_BLOCK_SIZE];
    size_t key_len;

    read_key(key, key_buffer, &key_len);

    print_key_length_warning(key_len);
    fill_key_with_zeros(key_buffer, key_len);

    unsigned char k_ipad[SHA1_BLOCK_SIZE];
    xor_with_ipad_or_opad(key_buffer, k_ipad, 0x36);

    if (EVP_DigestUpdate(ctx, k_ipad, SHA1_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error updating hash with K XOR ipad\n");
        exit(EXIT_FAILURE);
    }

    process_data(data, ctx);

    unsigned char partial[SHA1_DIGEST_SIZE];
    unsigned char final[SHA1_DIGEST_SIZE];
    
    finalize_hash(ctx, partial, key_buffer, final);

    EVP_MD_CTX_free(ctx);

    print_final_result(final, SHA1_DIGEST_SIZE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <data file> <key file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    FILE *data = fopen(argv[1], "rb");
    if (data == NULL) {
        fprintf(stderr, "Error opening data file\n");
        exit(EXIT_FAILURE);
    }

    FILE *key = fopen(argv[2], "rb");
    if (key == NULL) {
        fprintf(stderr, "Error opening key file\n");
        exit(EXIT_FAILURE);
    }

    compute_hmac_sha1(data, key);

    fclose(data);
    fclose(key);

    exit(EXIT_SUCCESS);
}
