from binascii import hexlify, unhexlify, b2a_base64, a2b_base64
from os import urandom


def hex2base64(input_hex):
    return b2a_base64(unhexlify(input_hex)).decode('utf-8')


def base642hex(input_base64):
    return hexlify(a2b_base64(input_base64))


def xor_strings(s1, s2):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2))


def xor_bytes(b1, b2):
    xor = b''
    for x, y in zip(b1, b2):
        xor += bytes([x ^ y])
    return xor


def hex2dec(string_hex):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(string_hex[0::2], string_hex[1::2])])


def dec2hex(string_dec):
    return hexlify(string_dec.encode('utf-8')).decode('utf-8')


def pad_pkcs(text, l):
    pad = (l - (len(text) % l)) % l
    return text + bytes([pad] * pad) if len(text) != 0 else bytes([l] * l)


def unpad_pkcs(text, l):
    if len(text) % l == 0:
        pad = text[-1]
        if pad > 16:
            return text
        else:
            return text[0:len(text) - pad]
    else:
        return text


def validate_pad_pkcs(text):
    # Supposed padding
    padding = text[-text[-1]:]
    # bytes in the range are equal to the padding value itself
    result = all(padding[b] == len(padding) for b in range(0, len(padding)))
    if not result:
        raise ValueError("wrong padding!")
    else:
        return result


def generate_aes_key():
    return urandom(16)


def random_bytes(n):
    return urandom(n)
