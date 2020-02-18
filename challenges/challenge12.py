from base64 import b64decode
from huepy import good, bad, run, info

from challenge07 import aes128_ecb_encrypt
from utils import pad_pkcs, generate_aes_key, read_data


class EncryptionOracleECB:
    def __init__(self, plain_text_data):
        self.key = generate_aes_key()
        self.data = plain_text_data

    def encrypt(self, plain_text):
        plain_text_pad = pad_pkcs(plain_text + b64decode(self.data), 16)
        cipher_text = aes128_ecb_encrypt(plain_text_pad, self.key)
        return cipher_text


def discover_block_size(encryption_oracle):
    '''
    Discover the block size of the cipher.
    Note: len(hex_string) = 2 * len(byte_string)
    '''
    test_data = b''
    initial_size = len(encryption_oracle.encrypt(test_data))
    test_size = initial_size
    while test_size == initial_size:
        test_data += b'A'
        encrypted_test_data = encryption_oracle.encrypt(test_data)
        test_size = len(encrypted_test_data)
    return test_size - initial_size


def detect_ecb_mode(encryption_oracle):
    '''
    This function detect if ECB mode is used
    The problem with ECB is that it is stateless and deterministic;
    the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    Due that, if we generate always the same data, the ecb mode will be always output
    the same ciphertext (except the random bytes added)
    '''
    test_data = bytes([0]) * 200
    encrypted_data = encryption_oracle.encrypt(test_data)

    blocks = [encrypted_data[i:i + 16] for i in range(0, len(encrypted_data), 16)]
    number_of_repeated_blocks = len(blocks) - len(set(blocks))

    return True if number_of_repeated_blocks else False


def find_byte(encryption_oracle, block_size, known_bytes):
    prefix_length = block_size - ((1 + len(known_bytes)) % block_size)
    prefix = bytes([0] * prefix_length)
    test_length = prefix_length + len(known_bytes) + 1
    real_ciphertext = encryption_oracle.encrypt(prefix)
    for i in range(256):
        test_ciphertext = encryption_oracle.encrypt(prefix + known_bytes + bytes([i]))
        if test_ciphertext[:test_length] == real_ciphertext[:test_length]:
            return bytes([i])
    return b''


if __name__ == '__main__':

    data = read_data('12')

    encryption_oracle = EncryptionOracleECB(data)

    print(run("Discovering block size..."))
    block_size = discover_block_size(encryption_oracle)
    print(good(f"Block size: {block_size} bytes"))
    if not detect_ecb_mode(encryption_oracle):
        print(bad("The cipher is NOT using ECB mode"))
    else:
        print(info("The cipher is using ECB mode"))
        decrypted_data = b''
        data_length = len(encryption_oracle.encrypt(b''))
        for i in range(data_length):
            next_byte = find_byte(encryption_oracle, block_size, decrypted_data)
            decrypted_data += next_byte
            # print(decrypted_data)
            print(run("Decrypting: " + "{:4.2f}".format(100 * (i + 1) / data_length) + "%"), end='\r')
        print(good("Decryption complete!"))
        print(decrypted_data.decode('utf-8'))
