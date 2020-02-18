from os import urandom
from random import randint
from huepy import info, good, run, lpurple, lblue, green, red

from challenge07 import aes128_ecb_encrypt
from challenge10 import aes128_cbc_encrypt
from utils import generate_aes_key, divide_in_blocks


def append_random_bytes(plain_text):
    """append 5-10 bytes (count chosen randomly) before the plaintext
    and 5-10 bytes after the plaintext."""
    return urandom(randint(5, 10)) + plain_text + urandom(randint(5, 10))


def encryption_oracle(plain_text):
    plain_text_ext = append_random_bytes(plain_text)

    key = generate_aes_key()
    if randint(0, 1):
        cipher_text = aes128_ecb_encrypt(plain_text_ext, key)
        print(info(f"Oracle: {lpurple('ECB')}"))
    else:
        iv = generate_aes_key()
        cipher_text = aes128_cbc_encrypt(plain_text_ext, iv, key)
        print(info(f"Oracle: {lblue('CBC')}"))

    return cipher_text


if __name__ == '__main__':
    '''
    This function detect if ECB of CBC mode is used
    The problem with ECB is that it is stateless and deterministic; the same
    16 byte plaintext block will always produce the same 16 byte ciphertext.
    Due that, if we generate always the same data, the ecb mode will be always
    output the same ciphertext (except the random bytes added)
    '''

    data = bytes([0]) * 200
    cipher_text = encryption_oracle(data)

    blocks = divide_in_blocks(cipher_text, 16)
    num_repeated_blocks = len(blocks) - len(set(blocks))

    if num_repeated_blocks:
        print(run(f"Number of repeated blocks: {red(num_repeated_blocks)}"))
        print(good(f"The cipher is using {lpurple('ECB')} mode"))
    else:
        print(run(f"Number of repeated blocks: {green(num_repeated_blocks)}"))
        print(good(f"The cipher is using {lblue('CBC')} mode"))
