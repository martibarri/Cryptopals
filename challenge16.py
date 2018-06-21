from challenge10 import aes128_cbc_encrypt, aes128_cbc_decrypt
from binascii import hexlify, unhexlify
from utils import pad_pkcs, unpad_pkcs, generate_aes_key


def parsing_routine(cookie_data):
    cookie_array = cookie_data.split(';')
    cookie_dict = {}
    for item in cookie_array:
        cookie_dict[item.split('=')[0]] = item.split('=')[1]
    return cookie_dict


class CBCBitflippingAttack:
    def __init__(self):
        key = generate_aes_key()
        self.key_hex = key.hex()
        iv = "\x00" * 16
        self.iv_hex = hexlify(iv.encode('utf-8')).decode('utf-8')

    def prepare(self, input_string):
        comment1 = b'comment1=cooking%20MCs;userdata='
        comment2 = b';comment2=%20like%20a%20pound%20of%20bacon'
        clean_input_string = input_string.translate({ord(c): None for c in '=;'})
        plain_text_pad = pad_pkcs(comment1 + clean_input_string.encode('utf-8') + comment2, 16)
        plain_text_hex = plain_text_pad.hex()
        encrypted_data_hex = aes128_cbc_encrypt(plain_text_hex, self.iv_hex, self.key_hex)
        return unhexlify(encrypted_data_hex.encode('utf-8'))

    def detect_admin(self, encrypted_data):
        encrypted_data_hex = encrypted_data.hex()
        plain_text_hex = aes128_cbc_decrypt(encrypted_data_hex, self.iv_hex, self.key_hex)
        plain_text = unpad_pkcs(unhexlify(plain_text_hex.encode('utf-8')), 16)  # TODO unpad_pkcs
        print("plain text decrypted unpadded", plain_text)
        data_dict = parsing_routine(plain_text.decode('utf-8', 'ignore'))
        return "admin" in data_dict and data_dict["admin"] == "true"


if __name__ == '__main__':
    bitflipping_attack = CBCBitflippingAttack()
    my_data = "data;admin=true"
    print("my data:", my_data)
    encrypted_data = bitflipping_attack.prepare(my_data)
    admin_detected = bitflipping_attack.detect_admin(encrypted_data)
    print("admin tuple:\n", admin_detected)

    print("\nnow let's break the crypto:\n")

    my_data = "asdas1admin0true"
    encrypted_data = bitflipping_attack.prepare(my_data)

    # modify the ciphertext
    altered1 = bytes([encrypted_data[21] ^ 59 ^ 49])  # ';' -> 59, '1' -> 49
    altered2 = bytes([encrypted_data[27] ^ 61 ^ 48])  # '=' -> 61, '0' -> 48
    modified_encrypted_data = encrypted_data[0:21] + altered1 + \
                              encrypted_data[22:27] + altered2 + encrypted_data[28:len(encrypted_data)]
    print("ciphertext modified...")
    admin_detected = bitflipping_attack.detect_admin(modified_encrypted_data)
    print("admin tuple:\n", admin_detected)
