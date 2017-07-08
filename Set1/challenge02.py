#  Write a function that takes two equal-length buffers and produces their XOR combination.
from binascii import unhexlify, hexlify

#string1_hex = input("Enter hex string1: ")
#string2_hex = input("Enter hex string2: ")
string1_hex = "1c0111001f010100061a024b53535009181c"
string2_hex = "686974207468652062756c6c277320657965"
string1_dec = unhexlify(string1_hex).decode('utf-8')
string2_dec = unhexlify(string2_hex).decode('utf-8')
print("string1_decoded: ", string1_dec)
print("string2_decoded: ", string2_dec)

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

xored_dec = xor_strings(string1_dec, string2_dec).encode('utf-8')
xored_hex = hexlify(xored_dec).decode('utf-8')
print("xored_decoded: ", xored_dec)
print("xored_hex: ", xored_hex)
