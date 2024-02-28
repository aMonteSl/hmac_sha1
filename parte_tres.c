#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHA1_LEN 20
#define BUFFER_SIZE 1024

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void fill_key_with_zeros(char *key) {
    int len = strlen(key);
    if (len < SHA1_LEN) {
        for (int i = len; i < SHA1_LEN; i++) {
            key[i] = '\0';  // Rellena con ceros
        }
    }
}

void xor_with_ipad(char *key) {
    char ipad[SHA1_LEN];
    memset(ipad, 0x36, SHA1_LEN); // Llena el array con 0x36
    for (int i = 0; i < SHA1_LEN; i++) {
        key[i] ^= ipad[i]; // Realiza la operación XOR
    }
}

void xor_with_opad(char *key) {
    char opad[SHA1_LEN];
    memset(opad, 0x5C, SHA1_LEN); // Llena el array con 0x5C
    for (int i = 0; i < SHA1_LEN; i++) {
        key[i] ^= opad[i]; // Realiza la operación XOR
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s <archivo_key> <archivo_datos>\n", argv[0]);
        return -1;
    }

    FILE *key_fp = fopen(argv[1], "rb"); // Abre la clave en modo binario
    if (key_fp == NULL) {
        perror("No se puede abrir el archivo de clave");
        return -1;
    }

    FILE *data_fp = fopen(argv[2], "rb"); // Abre los datos en modo binario
    if (data_fp == NULL) {
        perror("No se puede abrir el archivo de datos");
        fclose(key_fp);
        return -1;
    }

    char key[SHA1_LEN + 1]; // +1 para el terminador nulo
    size_t bytes_read = fread(key, 1, SHA1_LEN, key_fp);
    fclose(key_fp);

    if (bytes_read < SHA1_LEN) {
        fill_key_with_zeros(key);
    }

    xor_with_ipad(key);

    EVP_MD_CTX *c_digest = EVP_MD_CTX_new();
    if (c_digest == NULL) handleErrors();

    if (1 != EVP_DigestInit_ex(c_digest, EVP_sha1(), NULL)) handleErrors();

    unsigned char buffer[BUFFER_SIZE];

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, data_fp)) > 0) {
        if (1 != EVP_DigestUpdate(c_digest, buffer, bytes_read)) handleErrors();
    }

    fclose(data_fp);

    unsigned char hash_inner[SHA1_LEN];
    unsigned int sz_inner = SHA1_LEN;

    if (1 != EVP_DigestFinal_ex(c_digest, hash_inner, &sz_inner)) handleErrors();

    xor_with_opad(key);

    if (1 != EVP_DigestInit_ex(c_digest, EVP_sha1(), NULL)) handleErrors();
    if (1 != EVP_DigestUpdate(c_digest, key, SHA1_LEN)) handleErrors();
    if (1 != EVP_DigestUpdate(c_digest, hash_inner, SHA1_LEN)) handleErrors();

    unsigned char hash_outer[SHA1_LEN];
    unsigned int sz_outer = SHA1_LEN;

    if (1 != EVP_DigestFinal_ex(c_digest, hash_outer, &sz_outer)) handleErrors();

    EVP_MD_CTX_free(c_digest);

    for (unsigned int i = 0; i < sz_outer; i++) {
        printf("%02x", hash_outer[i]);
    }
    printf("\n");

    return 0;
}
