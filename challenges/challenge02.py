from binascii import hexlify
from utils import hex2dec, xor_strings
from huepy import run, info, good, bad


if __name__ == '__main__':

    # Write a function that takes two equal-length buffers
    # and produces their XOR combination.

    # If your function works properly, then when you feed it the string:
    string1_hex = "1c0111001f010100061a024b53535009181c"
    print(run(f'string1 hex: {string1_hex}'))
    string1_dec = hex2dec(string1_hex, True)
    print(run(f'string1 decoded: {string1_dec}'))

    # ... after hex decoding, and when XOR'd against:
    string2_hex = "686974207468652062756c6c277320657965"
    print(run(f'string2 hex: {string2_hex}'))
    string2_dec = hex2dec(string2_hex, True)
    print(run(f'string2 decoded: {string2_dec}'))

    # ... should produce:
    expected_result = "746865206b696420646f6e277420706c6179"
    xored_dec = xor_strings(string1_dec, string2_dec, bytes_out=True)
    print(info(f'xored_decoded: {xored_dec}'))
    xored_hex = hexlify(xored_dec).decode('utf-8')
    print(info(f'xored_hex: {xored_hex}'))
    print(info(f'expected_result: {xored_hex}'))
    if xored_hex == expected_result:
        print(good('result true'))
    else:
        print(bad('keep trying...'))
