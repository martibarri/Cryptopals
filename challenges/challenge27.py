from challenge10 import aes128_cbc_encrypt, aes128_cbc_decrypt
from utils import pad_pkcs, unpad_pkcs, xor_bytes


def parsing_routine(cookie_data):
    cookie_array = cookie_data.split(';')
    cookie_dict = {}
    for item in cookie_array:
        #  with random values it may result in appearing the character ';'
        #  which will result an IndexError Exception because the next expression
        #  won't find an equal ('=') to split the item. We will ignore this case
        try:
            cookie_dict[item.split('=')[0]] = item.split('=')[1]
        except IndexError:
            pass
    print(cookie_dict)
    return cookie_dict


class CBCBitflippingAttack:
    def __init__(self):
        self.key = b'YELLOW SUBMARINE'
        self.iv = self.key

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
        # rise an exception if decoded_plain_text is a noncompliant message
        try: 
            decoded_plain_text = plain_text.decode('utf-8')
        except Exception as e:
            print(e)
            # the exception returns the plain_text
            return plain_text
        data_dict = parsing_routine(decoded_plain_text)
        return "admin" in data_dict and data_dict["admin"] == "true"


if __name__ == '__main__':

    #  Recover the key from CBC with IV=Key

    bitflipping_attack = CBCBitflippingAttack()
    
    my_data = b'data'
    cipher_text = bitflipping_attack.prepare(my_data)  # len(cipher_text) = 80 -> 5 blocks
    # modify the ciphertext
    b0 = cipher_text[:16]
    b1 = cipher_text[16:32]
    b2 = cipher_text[32:48]
    b3 = cipher_text[48:64]
    b4 = cipher_text[64:]
    blank_block = bytes([0]) * 16
    modified_encrypted_data = b0 + blank_block + b0 + b3 + b4
    print("ciphertext modified...")
    admin_detected = bitflipping_attack.detect_admin(modified_encrypted_data)
    if type(admin_detected) != bool:
        plain_text = admin_detected
        print("plain_text:", plain_text)
        p0 = plain_text[:16]
        p2 = plain_text[32:48]
        iv = xor_bytes(p0, p2)
        print("iv:", iv)
    else:
        print("admin tuple:\n", admin_detected)
