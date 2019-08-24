import random
from os import urandom

from challenge07 import XorStates, matrix_to_bytes, string_to_matrix_states
from challenge21 import MT19937


def generate_8_bits(rng):
    """Generate a random 31-bit number, convert to binary and get the first 8 bits to return a new number"""
    number = rng.extract_number()  # 32 bits
    bin_number = bin(number)[2:].zfill(32)  # binary number keeping leading zeros so the result is always 32-bit
    byte_number = int(bin_number[:8], 2)  # 8 bits
    return byte_number


def generate_keytream_block(rng):
    """Build a 16-byte block using random bytes generated by rng"""
    block = b''
    for i in range(16):
        byte = chr(generate_8_bits(rng)).encode('utf8')
        block += bytes(byte)
    return block


def mt19937_cipher(input_string, seed):
    """
                               -----------------------
                               | Generated keystream |
                               -----------------------
    ------------------------              |
    | plain or cipher text | ---------> |XOR|
    ------------------------              |
                              ------------------------
                              | plain or cipher text |
                              ------------------------
    """
    output_string = b''
    # Initialize rng using key as a seed.
    rng = MT19937(seed)

    # Divide input string in blocks of 16 bytes
    input_text_blocks = [input_string[i:i + 16] for i in range(0, len(input_string), 16)]

    for i in range(len(input_text_blocks)):
        # Calculate keystream block for each input string block
        rng_block = generate_keytream_block(rng)
        rng_matrix = string_to_matrix_states(rng_block)[0]
        # Xor matrix
        d = XorStates(rng_matrix, string_to_matrix_states(input_text_blocks[i])[0])
        output_string += matrix_to_bytes(d)
    return output_string


def brute_force_mt19937_cipher(cipher, kwnon):
    print("Brute force all possible 16-bit keys...")
    for possible_key in range(2 ** 16):  # all 16-bit numbers
        result = mt19937_cipher(cipher_text, possible_key)
        if known_text in result:
            return possible_key
    return 0  # If no key found, return 0


if __name__ == '__main__':

    # Create the MT19937 stream cipher and break it

    key = random.getrandbits(16)  # Key: 16-bit seed

    # Encrypt 14 consecutive 'A' characters prefixed by a random number of random characters.
    known_text = b'A' * 14
    random_text = urandom(random.randint(1, 100))
    plain_text = random_text + known_text

    cipher_text = mt19937_cipher(plain_text, key)
    print("cipher_text:", cipher_text)

    # From the cipher_text, recover the "key" (the 16-bit seed)
    found_key = brute_force_mt19937_cipher(cipher_text, known_text)
    if found_key == key:
        print("found key", found_key, "correct")
        print("plain_text:", mt19937_cipher(cipher_text, found_key))
    else:
        print("found key", found_key, "NOT valid")