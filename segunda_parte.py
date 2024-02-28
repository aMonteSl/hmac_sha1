KEY_SIZE = 20
REPEAT_COUNT = 64

def fill_key_with_zeros(key):
    if len(key) < KEY_SIZE:
        key += '0' * (KEY_SIZE - len(key))
    return key

def xor_with_opad(key):
    opad = bytearray([0x5C] * KEY_SIZE)
    key_bytes = bytearray(key.encode())
    for i in range(KEY_SIZE):
        key_bytes[i] ^= opad[i]
    return key_bytes

def main():
    key_filename = input("Ingrese el nombre del archivo de clave: ")
    with open(key_filename, 'r') as key_file:
        key = key_file.readline().strip()

    key = fill_key_with_zeros(key)
    print("Clave leída:", key)

    key_bytes = xor_with_opad(key)
    print("Resultado:", ' '.join(format(x, '02x') for x in key_bytes))

if __name__ == "__main__":
    main()
