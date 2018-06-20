from challenge07 import aes128_ecb_encrypt, aes128_ecb_decrypt
from utils import pad_pkcs, unpad_pkcs, generate_aes_key
from binascii import hexlify, unhexlify


def parsing_routine(cookie_data):
    cookie_array = cookie_data.split('&')
    cookie_dict = {}
    for item in cookie_array:
        cookie_dict[item.split('=')[0]] = item.split('=')[1]
    return cookie_dict


class ProfileFactory:
    def __init__(self):
        self.uid = 10

    def profile_for(self, email):
        # delete '&' and '=' characters
        clean_email = email.translate({ord(c): None for c in '&='})
        formatted_profile = "email=" + clean_email + "&uid=" + str(self.uid) + "&role=user"
        self.uid += 1  # uid is incremental
        return formatted_profile


class System:
    def __init__(self):
        self.key = generate_aes_key()
        self.key_hex = hexlify(self.key).decode('utf-8')

    def encrypt_profile(self, email):
        '''Create profile from email and encrypt it using random key'''
        profile = profile_factory.profile_for(email)
        formatted_profile_pad = pad_pkcs(profile.encode('utf-8'), 16)
        formatted_profile_hex = hexlify(formatted_profile_pad).decode('utf-8')
        cipher_hex = aes128_ecb_encrypt(formatted_profile_hex, self.key_hex)
        return unhexlify(cipher_hex.encode('utf-8'))

    def decrypt_profile(self, encrypted_profile):
        encrypted_profile_hex = hexlify(encrypted_profile).decode('utf-8')
        decrypted_profile_hex = aes128_ecb_decrypt(encrypted_profile_hex, self.key_hex)
        unpadded_profile = unpad_pkcs(unhexlify(decrypted_profile_hex.encode('utf-8')), 16)
        return parsing_routine(unpadded_profile.decode('utf-8'))


if __name__ == '__main__':
    profile_factory = ProfileFactory()
    black_box_system = System()
    # profile1: email=foo@bar.co admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b &uid=10&role=user\x01
    email1 = "foo@bar.coadmin" + bytes([11] * 11).decode('utf-8')
    # profile2: email=foooo@bar. com&uid=11&role= user
    email2 = "foooo@bar.com"
    encrypted_profile1 = black_box_system.encrypt_profile(email1)
    encrypted_profile2 = black_box_system.encrypt_profile(email2)
    print("email1:", email1.encode('utf-8'))
    print(black_box_system.decrypt_profile(encrypted_profile1))
    print("email2:", email2.encode('utf-8'))
    print(black_box_system.decrypt_profile(encrypted_profile2))
    print("crafting profile...")
    crafted_profile = encrypted_profile2[0:32] + encrypted_profile1[16:32]
    print(black_box_system.decrypt_profile(crafted_profile))
