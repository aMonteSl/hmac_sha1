#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 20
#define REPEAT_COUNT 64

void fill_key_with_zeros(char *key) {
    int len = strlen(key);
    if (len < KEY_SIZE) {
        for (int i = len; i < KEY_SIZE; i++) {
            key[i] = '0';  // Rellena con ceros
        }
        key[KEY_SIZE] = '\0';  // Asegura que la cadena tenga un terminador nulo
    }
}

void xor_with_opad(char *key) {
    char opad[KEY_SIZE + 1];
    memset(opad, 0x5C, sizeof(opad)); // Llena el array con 0x5C
    for (int i = 0; i < KEY_SIZE; i++) {
        key[i] ^= opad[i]; // Realiza la operación XOR
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <archivo_key>\n", argv[0]);
        return 1;
    }

    char *key_filename = argv[1];
    FILE *key_file = fopen(key_filename, "r");
    if (key_file == NULL) {
        perror("Error al abrir el archivo de clave");
        return 1;
    }

    char key[KEY_SIZE + 1]; // +1 para el terminador nulo
    fgets(key, sizeof(key), key_file);
    fclose(key_file);

    // Eliminar el salto de línea final, si está presente
    char *newline = strchr(key, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }

    // Verificar la longitud de la clave
    int key_len = strlen(key);
    if (key_len < KEY_SIZE) {
        printf("La clave es muy corta. Rellenando con ceros...\n");
        fill_key_with_zeros(key);
    }

    // Realizar la operación XOR con la constante opad
    printf("Realizando operación XOR con la constante opad...\n");
    xor_with_opad(key);

    printf("Resultado: ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x ", (unsigned char)key[i]);
    }
    printf("\n");

    return 0;
}
