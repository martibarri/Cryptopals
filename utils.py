from binascii import hexlify, unhexlify, b2a_base64


def hex2base64(input_hex):
    return b2a_base64(unhexlify(input_hex)).decode('utf-8')


def xor_strings(s1, s2):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2))


def hex2dec(string_hex):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(string_hex[0::2], string_hex[1::2])])


def dec2hex(string_dec):
    return hexlify(string_dec.encode('utf-8')).decode('utf-8')