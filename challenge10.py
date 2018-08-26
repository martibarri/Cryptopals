from challenge07 import aes128_RoundBlock, aes128_InvRoundBlock, XorStates, matrix_to_bytes, string_to_matrix_states
from binascii import a2b_base64


def aes128_cbc_decrypt(cipher_text, iv, key):
    iv_matrix = string_to_matrix_states(iv)[0]  # assuming iv is a 16 bytes string, so a single state is created
    states = string_to_matrix_states(cipher_text)
    plain_text = b''
    for index, state in enumerate(states):
        if index == 0:
            d = XorStates(aes128_InvRoundBlock(state, key), iv_matrix)
        else:
            d = XorStates(aes128_InvRoundBlock(state, key), states[index - 1])
        plain_text += matrix_to_bytes(d)
    return plain_text


def aes128_cbc_encrypt(plain_text, iv, key):
    iv_matrix = string_to_matrix_states(iv)[0]  # assuming iv is a 16 bytes string, so a single state is created
    states = string_to_matrix_states(plain_text)
    cipher_text = b''
    previous_ciphertext_state = [[], [], [], []]
    for index, state in enumerate(states):
        if index == 0:
            e = aes128_RoundBlock(XorStates(state, iv_matrix), key)
        else:
            e = aes128_RoundBlock(XorStates(state, previous_ciphertext_state), key)
        previous_ciphertext_state = e
        cipher_text += matrix_to_bytes(e)
    return cipher_text


if __name__ == '__main__':

    # Implement CBC mode

    key = b'YELLOW SUBMARINE'

    iv = b'\x00' * 16

    f = open('sources/10.txt', 'r')
    encrypted_data_base64 = ""
    for line in f:
        encrypted_data_base64 += line.strip('\n')
    encrypted_data = a2b_base64(encrypted_data_base64)

    plain_text = aes128_cbc_decrypt(encrypted_data, iv, key)
    cipher_text = aes128_cbc_encrypt(plain_text, iv, key)

    if cipher_text == encrypted_data:
        print("---------- AES128 CBC MODE WORKS CORRECTLY ----------")
    else:
        print("---------- ERROR! ----------")

    print(plain_text.decode())
