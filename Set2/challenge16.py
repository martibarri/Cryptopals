from sys import path

path.insert(0, '../Set1')
from challenge09 import pad_PKCS
from challenge10 import aes128_cbc_encrypt, aes128_cbc_decrypt
from challenge11 import generate_aes_key
from challenge13 import unpad_PKCS
from binascii import hexlify, unhexlify


def parsing_routine(cookie_data):
    cookie_array = cookie_data.split(';')
    cookie_dict = {}
    for item in cookie_array:
        cookie_dict[item.split('=')[0]] = item.split('=')[1]
    return cookie_dict


class CBC_bitflipping_attack():
    def __init__(self):
        key = generate_aes_key()
        self.key_hex = hexlify(key).decode('utf-8')
        iv = "\x00" * 16
        self.iv_hex = hexlify(iv.encode('utf-8')).decode('utf-8')

    def prepare(self, input_string):
        comment1 = b'comment1=cooking%20MCs;userdata='
        comment2 = b';comment2=%20like%20a%20pound%20of%20bacon'
        clean_input_string = input_string.translate({ord(c): None for c in '=;'})
        plain_text_pad = pad_PKCS(comment1 + clean_input_string.encode('utf-8') + comment2, 16)
        print(plain_text_pad)
        plain_text_hex = hexlify(plain_text_pad).decode('utf-8')
        encrypted_data_hex = aes128_cbc_encrypt(plain_text_hex, self.iv_hex, self.key_hex)
        return unhexlify(encrypted_data_hex.encode('utf-8'))

    def detect_admin(self, encrypted_data):
        encrypted_data_hex = hexlify(encrypted_data).decode('utf-8')
        plain_text_hex = aes128_cbc_decrypt(encrypted_data_hex, self.iv_hex, self.key_hex)
        plain_text = unpad_PKCS(unhexlify(plain_text_hex.encode('utf-8')), 16)
        print(plain_text)
        data_dict = parsing_routine(plain_text.decode('utf-8'))
        print(data_dict)
        return "admin" in data_dict and data_dict["admin"] == "true"


if __name__ == '__main__':
    bitflipping_attack = CBC_bitflipping_attack()
    encrypted_data = bitflipping_attack.prepare("aaaaaaaaaaa")
    print(encrypted_data)
    print(bitflipping_attack.detect_admin(encrypted_data))
