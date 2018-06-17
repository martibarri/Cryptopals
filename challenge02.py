#  Write a function that takes two equal-length buffers and produces their XOR combination.
from binascii import unhexlify, hexlify


def xor_strings(s1, s2):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2))


if __name__ == '__main__':
    string1_hex = "1c0111001f010100061a024b53535009181c"
    print("string1_hex:", string1_hex)
    string1_dec = unhexlify(string1_hex).decode('utf-8')
    print("string1_decoded:", string1_dec)
    string2_hex = "686974207468652062756c6c277320657965"
    print("string2_hex:", string2_hex)
    string2_dec = unhexlify(string2_hex).decode('utf-8')
    print("string2_decoded:", string2_dec)

    xored_dec = xor_strings(string1_dec, string2_dec).encode('utf-8')
    print("xored_decoded: ", xored_dec)
    xored_hex = hexlify(xored_dec).decode('utf-8')
    print("xored_hex: ", xored_hex)
    if xored_hex == "746865206b696420646f6e277420706c6179":
        print("result true")
