from challenge10 import aes128_cbc_encrypt, aes128_cbc_decrypt
from utils import pad_pkcs, unpad_pkcs, generate_aes_key


def parsing_routine(cookie_data):
    cookie_array = cookie_data.split(';')
    cookie_dict = {}
    for item in cookie_array:
        cookie_dict[item.split('=')[0]] = item.split('=')[1]
    print(cookie_dict)
    return cookie_dict


class CBCBitflippingAttack:
    def __init__(self):
        self.key = generate_aes_key()
        self.iv = bytes([0]) * 16

    def prepare(self, input_string):
        comment1 = b'comment1=cooking%20MCs;userdata='
        comment2 = b';comment2=%20like%20a%20pound%20of%20bacon'
        table = str.maketrans(dict.fromkeys('=;'))
        clean_input_string = input_string.decode().translate(table)
        plain_text_pad = pad_pkcs(comment1 + clean_input_string.encode() + comment2, 16)
        return aes128_cbc_encrypt(plain_text_pad, self.iv, self.key)

    def detect_admin(self, cipher_text):
        plain_text = aes128_cbc_decrypt(cipher_text, self.iv, self.key)
        plain_text = unpad_pkcs(plain_text, 16)
        print("plain text decrypted unpadded:", plain_text)
        data_dict = parsing_routine(plain_text.decode('utf-8', 'ignore'))
        return "admin" in data_dict and data_dict["admin"] == "true"


if __name__ == '__main__':
    bitflipping_attack = CBCBitflippingAttack()
    my_data = b'data;admin=true'
    print("my data:", my_data)
    cipher_text = bitflipping_attack.prepare(my_data)
    admin_detected = bitflipping_attack.detect_admin(cipher_text)
    print("admin tuple:\n", admin_detected)

    print("\nnow let's break the crypto:\n")

    my_data = b'asdas1admin0true'
    print("my data:", my_data)
    cipher_text = bitflipping_attack.prepare(my_data)

    # modify the ciphertext
    altered1 = bytes([cipher_text[21] ^ 59 ^ 49])  # ';' -> 59, '1' -> 49
    altered2 = bytes([cipher_text[27] ^ 61 ^ 48])  # '=' -> 61, '0' -> 48
    modified_encrypted_data = cipher_text[0:21] + altered1 + \
                              cipher_text[22:27] + altered2 + cipher_text[28:len(cipher_text)]
    print("ciphertext modified...")
    admin_detected = bitflipping_attack.detect_admin(modified_encrypted_data)
    print("admin tuple:\n", admin_detected)
