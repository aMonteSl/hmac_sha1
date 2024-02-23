#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <err.h>

int main(int argc, char *argv[]){
    char data [] = "hola\n";
    unsigned char hash[20];
    int i;
    EVP_MD_CTX *c;
    unsigned int sz;

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL){
        printf("No se puede abrir el fichero\n");
        return -1;
    }

    // size_t fread(void * buffer, sizeof(char), size_t )


    c = EVP_MD_CTX_new();
    if (c == NULL) {
        errx(1, "EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit(c, EVP_sha1())){
        errx(1, "SHA1 EVP_DigetsInit failed");
    }
    if (!EVP_DigestUpdate(c, data, strlen(data))){
        errx(1, "EVP_DigestUpdate failed");
    }
    if (!EVP_DigestFinal_ex(c, hash, &sz) || sz != EVP_MD_size(EVP_sha1())){
        errx(1, "EVP_DigestFInal_ex failed");
    }

    EVP_MD_CTX_free(c);
    for (i = 0; i < sz; i++){
        printf("%02x", (unsigned char)hash[i]);
    }
    printf("\n");


}