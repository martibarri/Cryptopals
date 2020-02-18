from binascii import a2b_base64

from challenge07 import aes128_RoundBlock
from utils import validate_pad_pkcs, unpad_pkcs, \
    xor_states, matrix_to_bytes, string_to_matrix_states


def aes128_ctr_cipher(string, nonce, key):
    """
                                  ------------------
                                  | nonce + counter|
                                  ------------------
                                          |
                                     -----------
                                     | encrypt |
                                     -----------
    ------------------------              |
    | plain or cipher text | ---------> |XOR|
    ------------------------              |
                              ------------------------
                              | plain or cipher text |
                              ------------------------
    """
    cipher_string = b''
    # Divide input string in blocks of 16 bytes
    cipher_text_blocks = [string[i:i + 16] for i in range(0, len(string), 16)]
    for i in range(len(cipher_text_blocks)):
        # Calculate incremental nonce block for each input string block
        nonce_block = nonce + i.to_bytes(8, byteorder='little')
        nonce_matrix = string_to_matrix_states(nonce_block)[0]
        # Cipher nonce block with key
        nonce_matrix_cipher = aes128_RoundBlock(nonce_matrix, key)
        d = xor_states(nonce_matrix_cipher, string_to_matrix_states(cipher_text_blocks[i])[0])
        cipher_string += matrix_to_bytes(d)
    return cipher_string


if __name__ == '__main__':

    # Implement CTR mode

    encrypted_data_base64 = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    encrypted_data = a2b_base64(encrypted_data_base64)
    key = b'YELLOW SUBMARINE'
    nonce = bytes([0]) * 8  # nonce forced to 0
    #  format = 64 bit unsigned little endian nonce,
    #           64 bit little endian block count (byte count / 16)

    plain_text = aes128_ctr_cipher(encrypted_data, nonce, key)
    cipher_text = aes128_ctr_cipher(plain_text, nonce, key)

    if validate_pad_pkcs(cipher_text):
        print("cipher_text padded, unpadding...")
        cipher_text = unpad_pkcs(cipher_text, 16)

    if cipher_text == encrypted_data:
        print("---------- AES128 CTR MODE WORKS CORRECTLY ----------")
    else:
        print("---------- ERROR! ----------")

    print(plain_text)
