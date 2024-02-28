#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <archivo_datos> <archivo_clave>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *data_file = fopen(argv[1], "rb");
    if (!data_file) {
        perror("No se pudo abrir el archivo de datos");
        return EXIT_FAILURE;
    }

    FILE *key_file = fopen(argv[2], "rb");
    if (!key_file) {
        perror("No se pudo abrir el archivo de clave");
        fclose(data_file);
        return EXIT_FAILURE;
    }

    unsigned char key[64]; // Tamaño máximo de clave
    size_t key_length = fread(key, 1, sizeof(key), key_file);
    if (key_length == 0) {
        fprintf(stderr, "No se pudo leer la clave del archivo\n");
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    if (key_length < 20) {
        fprintf(stderr, "warning: la clave es muy corta (debería ser más larga que 20 bytes)\n");
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        perror("No se pudo crear el contexto de hash");
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    if (!EVP_DigestInit(ctx, EVP_sha1())) {
        perror("No se pudo inicializar el contexto de hash");
        EVP_MD_CTX_free(ctx);
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), data_file)) > 0) {
        if (!EVP_DigestUpdate(ctx, buffer, bytes_read)) {
            perror("Error al actualizar el contexto de hash");
            EVP_MD_CTX_free(ctx);
            fclose(data_file);
            fclose(key_file);
            return EXIT_FAILURE;
        }
    }

    if (ferror(data_file)) {
        perror("Error al leer el archivo de datos");
        EVP_MD_CTX_free(ctx);
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    if (!EVP_DigestUpdate(ctx, key, key_length)) {
        perror("Error al agregar la clave al contexto de hash");
        EVP_MD_CTX_free(ctx);
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    if (!EVP_DigestUpdate(ctx, "\n", 1)) {
        perror("Error al agregar el carácter de nueva línea al contexto de hash");
        EVP_MD_CTX_free(ctx);
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_length)) {
        perror("Error al finalizar el contexto de hash");
        EVP_MD_CTX_free(ctx);
        fclose(data_file);
        fclose(key_file);
        return EXIT_FAILURE;
    }

    print_hex(hash, hash_length);
    printf("\n");

    EVP_MD_CTX_free(ctx);
    fclose(data_file);
    fclose(key_file);
    return EXIT_SUCCESS;
}
