#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s <archivo> <clave>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("No se puede abrir el archivo");
        return 1;
    }

    // La clave para el HMAC
    unsigned char *key = (unsigned char *)argv[2];
    size_t key_len = strlen(argv[2]);

    // Inicializar variables para OpenSSL
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) handleErrors();

    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    if (!hmac_ctx) handleErrors();

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA1", 0),
        OSSL_PARAM_construct_octet_string("key", key, key_len),
        OSSL_PARAM_construct_end()
    };

    if (1 != EVP_MAC_CTX_set_params(hmac_ctx, params))
        handleErrors();

    if (1 != EVP_MAC_init(hmac_ctx, key, key_len, NULL)) // Corregido aquí
        handleErrors();

    // Leer el archivo y alimentar los datos al HMAC
    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (1 != EVP_MAC_update(hmac_ctx, buffer, bytes_read))
            handleErrors();
    }
    fclose(fp);

    // Obtener el resultado del HMAC
    unsigned char result[EVP_MAX_MD_SIZE];
    size_t result_len;
    if (1 != EVP_MAC_final(hmac_ctx, result, &result_len, sizeof(result)))
        handleErrors();

    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);

    // Imprimir el HMAC en hexadecimal
    for (size_t i = 0; i < result_len; i++) {
        printf("%02x", result[i]);
    }
    printf("\n");

    return 0;
}
