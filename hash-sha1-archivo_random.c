#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#define SHA1_LEN 20
#define BUFFER_SIZE 1024

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <archivo>\n", argv[0]);
        return -1;
    }

    FILE *fp = fopen(argv[1], "rb"); // Abre en modo binario
    if (fp == NULL) {
        perror("No se puede abrir el fichero");
        return -1;
    }

    EVP_MD_CTX *c_digest = EVP_MD_CTX_new();
    if (c_digest == NULL) handleErrors();

    if (1 != EVP_DigestInit_ex(c_digest, EVP_sha1(), NULL)) handleErrors();

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        if (1 != EVP_DigestUpdate(c_digest, buffer, bytes_read)) handleErrors();
    }

    fclose(fp);

    unsigned char hash[SHA1_LEN];
    unsigned int sz = SHA1_LEN;

    if (1 != EVP_DigestFinal_ex(c_digest, hash, &sz)) handleErrors();

    EVP_MD_CTX_free(c_digest);

    for (unsigned int i = 0; i < sz; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}


