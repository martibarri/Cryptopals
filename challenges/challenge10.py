from binascii import a2b_base64
from huepy import good, bad

from challenge07 import aes128_RoundBlock, aes128_InvRoundBlock
from utils import read_data, xor_states, matrix_to_bytes, string_to_matrix_states


def aes128_cbc_decrypt(cipher_text, iv, key):
    # assuming iv is a 16 bytes string, so a single state is created
    iv_matrix = string_to_matrix_states(iv)[0]
    states = string_to_matrix_states(cipher_text)
    plain_text = b''
    for index, state in enumerate(states):
        if index == 0:
            d = xor_states(aes128_InvRoundBlock(state, key), iv_matrix)
        else:
            d = xor_states(aes128_InvRoundBlock(state, key), states[index - 1])
        plain_text += matrix_to_bytes(d)
    return plain_text


def aes128_cbc_encrypt(plain_text, iv, key):
    # assuming iv is a 16 bytes string, so a single state is created
    iv_matrix = string_to_matrix_states(iv)[0]
    states = string_to_matrix_states(plain_text)
    cipher_text = b''
    pre_ciphertext_state = [[], [], [], []]
    for index, state in enumerate(states):
        if index == 0:
            e = aes128_RoundBlock(xor_states(state, iv_matrix), key)
        else:
            e = aes128_RoundBlock(xor_states(state, pre_ciphertext_state), key)
        pre_ciphertext_state = e
        cipher_text += matrix_to_bytes(e)
    return cipher_text


if __name__ == '__main__':

    # Implement CBC mode

    key = b'YELLOW SUBMARINE'

    iv = b'\x00' * 16

    encrypted_data_base64 = read_data('10')
    encrypted_data = a2b_base64(encrypted_data_base64)

    plain_text = aes128_cbc_decrypt(encrypted_data, iv, key)
    cipher_text = aes128_cbc_encrypt(plain_text, iv, key)

    if cipher_text == encrypted_data:
        print(good('AES128 CBC MODE WORKS CORRECTLY'))
    else:
        print(bad('ERROR!'))

    print(plain_text.decode())
