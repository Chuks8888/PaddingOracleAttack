from oracle import Oracle
oracle = Oracle()

def checkPadding(oracle, c0_bytearray, c1_bytearray):
    c0_hex = c0_bytearray.hex()
    c1_hex = c1_bytearray.hex()

    c0_string = '0x' + c0_hex
    c1_string = '0x' + c1_hex

    return oracle.pad_oracle(c0_string, c1_string)

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
    pass



