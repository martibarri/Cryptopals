from binascii import a2b_base64
from termcolor import cprint

from challenge18 import aes128_ctr_cipher
from challenge07 import aes128_ecb_decrypt
from utils import generate_aes_key, random_bytes, read_data


pre = ''
output = ''


def beautify_print():
    global pre
    global output
    print("\033c")
    cprint(pre, 'blue', attrs=['bold'])
    cprint(output, 'green')


def beautify_print_try(value):
    global pre
    global output
    print("\033c")
    cprint(pre, 'blue', attrs=['bold'])
    cprint(output, 'cyan')
    cprint('\n[~] Try: ' + value, 'yellow',)


def calculate_next_byte(ciphertext, offset):
    """
    cipher_text = plain_text XOR keystream
    new_cipher_text = new_plain_text XOR keystream
    plain_text = new_cipher_text XOR cipher_text XOR new_plain_text
    if cipher_text == new_cipher_text:
        plain_text = 0 XOR new_plain_text = new_plain_text
    We have to find bytes to cancel ciphertexts!
    """
    global output
    # we are looking for plaintext characters, so only `string.printable` are needed
    # string.printable manually ordered
    printable = 'abcdefghijklmnopqrstuvwxyz \n\'ABCDEFGHIJKLMNOPQRSTUVWXYZ"!?,-.:;0123456789#$%&()*+/<=>@[\\]^_`{|}~\t\r\x0b\x0c'
    for b in printable:
        new_ciphertext = ctr_system.edit_ctr(ciphertext, offset, b.encode())
        beautify_print_try(b)
        if new_ciphertext[offset] == ciphertext[offset]:
            output += b
            beautify_print()
            return b.encode()
    return b''


class CTR_system:
    def __init__(self):
        self.key = generate_aes_key()
        self.nonce = random_bytes(8)

    def cipher(self, text):
        return aes128_ctr_cipher(text, self.nonce, self.key)
    
    def edit_ctr(self, ciphertext, offset, newtext):
        # decrypt
        plaintext = aes128_ctr_cipher(ciphertext, self.nonce, self.key)
        # edit with different plaintext (newtext)
        new_plaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
        # encrypt again
        new_ciphertext = aes128_ctr_cipher(new_plaintext, self.nonce, self.key)
        return new_ciphertext


if __name__ == '__main__':

    pre += '[*] Using aes128_ecb_decrypt from challenge07 to decrypt provided data...\n'
    encrypted_data_base64 = read_data('25')
    encrypted_data = a2b_base64(encrypted_data_base64)

    ecb_key = b'YELLOW SUBMARINE'
    recovered_plain_text = aes128_ecb_decrypt(encrypted_data, ecb_key)

    ctr_system = CTR_system()

    pre += '[*] Encrypt the recovered plaintext under CTR with a random key...\n'
    cipher_text = ctr_system.cipher(recovered_plain_text)

    # Cipher text has been trimmed to improve speed of cracking 
    # Comment these lines to retrieve full text (slower):
    cipher_text = cipher_text[:200]
    recovered_plain_text = recovered_plain_text[:200]

    pre += '[*] Recover the original plaintext using the `edit_ctr()` function to crack ciphertext:\n'
    plain_text = b''
    for i in range(len(cipher_text)):
        new_byte = calculate_next_byte(cipher_text, i)
        plain_text += new_byte

    if plain_text == recovered_plain_text:
        cprint("\n[+] Plaintext retrieved correctly.", 'green', attrs=['bold'])
    else:
        cprint('\n[-] Recovered plaintext does not match the original one!', 'red', attrs=['bold'])
