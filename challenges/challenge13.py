from challenge07 import aes128_ecb_encrypt, aes128_ecb_decrypt
from utils import pad_pkcs, unpad_pkcs, generate_aes_key


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
        table = str.maketrans(dict.fromkeys('&='))
        clean_email = email.decode().translate(table)
        formatted_profile = "email=" + clean_email + "&uid=" + str(self.uid) + "&role=user"
        self.uid += 1  # uid is incremental
        return formatted_profile.encode()


class System:
    def __init__(self):
        self.key = generate_aes_key()

    def encrypt_profile(self, email):
        '''Create profile from email and encrypt it using random key'''
        profile = profile_factory.profile_for(email)
        formatted_profile_pad = pad_pkcs(profile, 16)
        cipher_text = aes128_ecb_encrypt(formatted_profile_pad, self.key)
        return cipher_text

    def decrypt_profile(self, encrypted_profile):
        decrypted_profile = aes128_ecb_decrypt(encrypted_profile, self.key)
        unpadded_profile = unpad_pkcs(decrypted_profile, 16)
        return parsing_routine(unpadded_profile.decode())


if __name__ == '__main__':
    profile_factory = ProfileFactory()
    black_box_system = System()
    # profile1: email=foo@bar.co admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b &uid=10&role=user\x01
    email1 = b'foo@bar.coadmin' + bytes([11] * 11)
    # profile2: email=foooo@bar. com&uid=11&role= user
    email2 = b'foooo@bar.com'
    encrypted_profile1 = black_box_system.encrypt_profile(email1)
    encrypted_profile2 = black_box_system.encrypt_profile(email2)
    print("email1:", email1)
    print(black_box_system.decrypt_profile(encrypted_profile1))
    print("email2:", email2)
    print(black_box_system.decrypt_profile(encrypted_profile2))
    print("crafting profile...")
    crafted_profile = encrypted_profile2[0:32] + encrypted_profile1[16:32]
    print(black_box_system.decrypt_profile(crafted_profile))
