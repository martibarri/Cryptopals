from utils import xor_strings, dec2hex
from huepy import good, bad


def encrypt_repeating_key_xor(key, input_string):
    encrypted = ""
    for i in range(int(len(input_string) / len(key) + 1)):
        substring = input_string[i * len(key):(i + 1) * len(key)]
        encrypted += xor_strings(substring, key)
    return dec2hex(encrypted)


if __name__ == '__main__':

    # Implement repeating-key XOR

    input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    # input_string = input("Enter string: ")
    # key = input("Enter key: ")

    encrypted_string = encrypt_repeating_key_xor(key, input_string)

    expected_result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    if encrypted_string == expected_result:
        print(good('Encryption correct'))
    else:
        print(bad('Encryption incorrect'))
