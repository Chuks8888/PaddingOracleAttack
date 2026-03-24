import sys
import os
from oracle import Oracle

def oracle_plaintext(oracle, iv_bytearray, c_bytearray):
    iv_hex = iv_bytearray.hex()
    c_hex = c_bytearray.hex()

    iv_string = '0x' + iv_hex
    c_string = '0x' + c_hex

    hex_plaintext = oracle.dec_oracle(iv_string, c_string)
    return bytearray.fromhex(hex_plaintext[2:])

def encrypt_block(oracle, iv_bytearray, c_bytearray, p_bytearray):
    oracle_bytearray = oracle_plaintext(oracle, iv_bytearray, c_bytearray)
    encryption = bytearray(8)

    for i in range(8):
        encryption[i] = p_bytearray[i] ^ oracle_bytearray[i] ^ iv_bytearray[i]

    return encryption

def encrypt_plaintext(oracle, bytearray_list):
    random_bytes = os.urandom(8)
    c_bytearray = bytearray(random_bytes)
    iv_bytearray = bytearray(8)

    cypher = []
    cypher.append(c_bytearray)

    for i in range(len(bytearray_list) - 1, -1, -1):
        cypher_block = encrypt_block(oracle, iv_bytearray, c_bytearray, bytearray_list[i])
        c_bytearray = cypher_block
        cypher.append(c_bytearray)

    cypher.reverse()
    return cypher

def split_message(message):
    bytearray_list = []

    message_bytearray = bytearray(message.encode('utf-8'))

    padding_length = 8 - (len(message_bytearray) % 8)
    for i in range(padding_length):
        message_bytearray.append(padding_length)

    for i in range(0, len(message_bytearray), 8):
        bytearray_list.append(message_bytearray[i:i+8])

    return bytearray_list

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)

    message = sys.argv[1]
    bytearray_list = split_message(message)

    oracle = Oracle()
    cypher = encrypt_plaintext(oracle, bytearray_list)

    result = []
    for block in cypher:
        result.append("0x" + block.hex())

    print("\t".join(result), end="")

    


