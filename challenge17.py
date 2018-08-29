from challenge10 import aes128_cbc_encrypt, aes128_cbc_decrypt
from binascii import a2b_base64
from utils import pad_pkcs, unpad_pkcs, validate_pad_pkcs, generate_aes_key, random_bytes
from random import randint


class CBCPaddingOracle:
    def __init__(self):
        self.key = generate_aes_key()
        self.iv = random_bytes(16)

    def encrypt(self, str):
        str_pad = pad_pkcs(str, 16)
        cipher_text = aes128_cbc_encrypt(str_pad, self.iv, self.key)
        return cipher_text, self.iv

    def decrypt(self, cipher_text, iv):
        plain_text = aes128_cbc_decrypt(cipher_text, iv, self.key)
        try:
            validate_pad_pkcs(plain_text)
        except ValueError:
            return False
        return True


def create_modified_block(iv, guessed_byte, padding_len, found_plaintext):
    """Creates a modified ciphertext block, ideally to be given as IV to decrypt the following block.
    The modified IV will be used for the attack on the padding oracle CBC encryption.
    """

    index_of_mod_char = len(iv) - padding_len  # index of the padding char

    mod_char = iv[index_of_mod_char] ^ guessed_byte ^ padding_len

    # Form the modified ciphertext by adding the modified character
    modified_block = iv[:index_of_mod_char] + bytes([mod_char])

    # Add already decrypted characters
    d = 0
    for k in range(16 - padding_len + 1, 16):
        forced_character = iv[k] ^ found_plaintext[d] ^ padding_len
        modified_block += bytes([forced_character])
        d += 1

    return modified_block


def decipher(ciphertext, oracle, iv):
    """
    ------   ---------------
    | iv |   | cipher_text |
    ------   ---------------
       |            |           iv_mod[i] = iv[i] ^ guessed_byte ^ padding_len
       |       -----------
       |       | decrypt |      plain_text_mod[i] = decrypt(cipher_text[i]) ^ iv_mod[i]
       |       -----------          = decrypt(cipher_text[i]) ^ iv[i] ^ guessed_byte ^ padding_len
       |            |               = plain_text[i] ^ guessed_byte ^ padding_len
       ---------->|XOR|
                    |           if (plain_text[i] ^ guessed_byte) == 0, (plain_text_mod[i] == padding_len)
              --------------    oracle.decrypt() will be True and plain_text[i] will be the guessed_byte!
              | plain_text |
              --------------
    """
    plaintext = b''
    # Split the ciphertext in blocks and add IV
    ciphertext_blocks = [iv] + [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    print(len(ciphertext_blocks) - 1, "blocks to decrypt")
    for c in range(1, len(ciphertext_blocks)):
        plaintext_block = b''

        for i in range(15, -1, -1):  # 15 to 0
            #  The padding_len will depend on how many chars we have already decrypted.
            padding_len = len(plaintext_block) + 1

            possible_last_bytes = []
            for g in range(256):
                # Create a IV with the guessed character g
                forced_iv = create_modified_block(ciphertext_blocks[c - 1], g, padding_len, plaintext_block)
                if oracle.decrypt(ciphertext_blocks[c], forced_iv) is True:
                    possible_last_bytes += bytes([g])

            # If we were trying to find the last character of block: b'of bacon\x08\x08\x08\x08\x08\x08\x08\x08'
            # bytes \x01 and \x08 would have valid padding.
            # To find the correct one, we can try the next character too.
            if len(possible_last_bytes) != 1:
                for byte in possible_last_bytes:
                    for g in range(256):
                        forced_iv = create_modified_block(ciphertext_blocks[c - 1], g, padding_len + 1,
                                                          bytes([byte]) + plaintext_block)
                        if oracle.decrypt(ciphertext_blocks[c], forced_iv) is True:
                            possible_last_bytes = [byte]
                            break

            # Add decrypted byte to the plaintext_block
            plaintext_block = bytes([possible_last_bytes[0]]) + plaintext_block
            print("Decrypting block " + str(c) + ": {:4.2f}".format(100 * (16 - i) / 16) + "%", end='\r')

        plaintext += plaintext_block
        print()

    return unpad_pkcs(plaintext, 16)


if __name__ == '__main__':

    f = open('sources/17.txt', 'r')
    random_strings = []
    for line in f:
        random_strings.append(line.strip('\n'))
    random_str = a2b_base64(random_strings[randint(0, 9)])

    cbc_padding_oracle = CBCPaddingOracle()
    cipher_text, iv = cbc_padding_oracle.encrypt(random_str)
    print("cipher text given:", cipher_text)
    print("iv used:", iv)

    text = decipher(cipher_text, cbc_padding_oracle, iv)
    print("Plain text decrypted:")
    print(text)
