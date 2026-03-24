from oracle import Oracle
oracle = Oracle()

def check_padding(oracle, c0_bytearray, c1_bytearray):
    check_padding.query_count += 1

    c0_hex = c0_bytearray.hex()
    c1_hex = c1_bytearray.hex()

    c0_string = '0x' + c0_hex
    c1_string = '0x' + c1_hex

    ret_pad = oracle.pad_oracle(c0_string, c1_string)
    return ret_pad == b'1'

def padding_length(oracle, c0, c1):
    modified_c0 = bytearray(c0)

    for i in range(2, 8):
        if i == 3:
            modified_c0[7] = c0[7]
            modified_c0[6] ^= 0x01
            result = check_padding(oracle, modified_c0, c1)

            if result == True:
                return 1
            
            modified_c0[6] = c0[6]


        modified_c0[7] = 0x01 ^ i ^ c0[7]
        result = check_padding(oracle, modified_c0, c1)

        if result == True:
            return i
        
    return 8

def ascii_plaintext(oracle, c0, c1, padding_length):
    plaintext = bytearray(8)
    intermediate = bytearray(8)

    starting_index = 8 - padding_length
    for i in range(starting_index, 8):
        plaintext[i] = padding_length
        intermediate[i] = c0[i] ^ padding_length

    priority = ['etaoinsrhldcumfpgwybvkxjqz', '0123456789', '!?_"()/@#$%^&*', 'ETAOINSRHLDCUMFPGWYBVKXJQZ']

    for current_index in range(starting_index -1, -1, -1):
        modified_c0 = bytearray(c0)
        current_padding = 8 - current_index

        for i in range(current_index + 1, 8):
            modified_c0[i] = current_padding ^ intermediate[i]

        found = False
        for str in priority:
            for guess in str.encode("utf-8"):
                modified_c0[current_index] = current_padding ^ guess ^ c0[current_index]

                if check_padding(oracle, modified_c0, c1):
                    plaintext[current_index] = guess
                    intermediate[current_index] = guess ^ c0[current_index]

                    found = True
                    break
            if found == True:
                break

        # for guess in range(33, 127):
        #     modified_c0[current_index] = current_padding ^ guess ^ c0[current_index]

        #     if check_padding(oracle, modified_c0, c1):
        #         plaintext[current_index] = guess
        #         intermediate[current_index] = guess ^ c0[current_index]

        #         break

    return plaintext[:-padding_length].decode('ascii')

check_padding.query_count = 0
data = []

with open('p1_ciphertexts.txt', 'r') as ciphers:
    for line in ciphers:
        parts = line.strip().split('\t')

        if len(parts) == 2:
            iv_hex = parts[0]
            c1_hex = parts[1]

            iv = bytearray.fromhex(iv_hex[2:])
            c1 = bytearray.fromhex(c1_hex[2:])
            data.append((iv, c1))

for c0, c1 in data:
    length = padding_length(oracle, c0, c1)
    print(ascii_plaintext(oracle, c0, c1, length))

print(f"Total Oracle Accesses: {check_padding.query_count}")