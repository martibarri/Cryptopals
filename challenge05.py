from binascii import hexlify


def encrypt_repeating_key_xor(key, input_string):
    encrypted = ""
    for i in range(int(len(input_string) / len(key) + 1)):
        substring = input_string[i * len(key):(i + 1) * len(key)]
        encrypted += "".join(chr(ord(x) ^ ord(y)) for x, y in zip(substring, key))
    return hexlify(encrypted.encode('utf-8')).decode('utf-8')


if __name__ == '__main__':
    # Implement repeating-key XOR
    input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    # input_string = input("Enter string: ")
    # key = input("Enter key: ")

    encrypted_string = encrypt_repeating_key_xor(key, input_string)
    print(encrypted_string)

    test = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    if encrypted_string == test:
        print("Encryption correct")
    else:
        print("Encryption incorrect")
