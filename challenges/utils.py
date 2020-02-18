from binascii import hexlify, unhexlify, b2a_base64, a2b_base64
from os import urandom


def read_data(challenge_number: (str, int), out_multiline: bool = False) -> (str, list):
    """Read provided file and return and return data"""
    data = [] if out_multiline else ""
    f = open(f'sources/{str(challenge_number)}.txt', 'r')
    for line in f:
        if out_multiline:
            data.append(line.strip())
        else:
            data += line.strip()
    return data


def hex2base64(input_hex: (str, bytes), bytes_out: bool = False) -> (str, bytes):
    """Convert from hexadecimal to base64."""
    if bytes_out:
        return b2a_base64(unhexlify(input_hex))
    else:
        return b2a_base64(unhexlify(input_hex)).decode('utf-8')


def base642hex(input_base64: (str, bytes), bytes_out: bool = False) -> (str, bytes):
    """Convert from base64 to hexadecimal."""
    if bytes_out:
        return hexlify(a2b_base64(input_base64))
    else:
        return hexlify(a2b_base64(input_base64)).decode('utf-8')


def xor_strings(s1: (str, bytes), s2: (str, bytes), bytes_out: bool = False) -> (str, bytes):
    try:
        xored = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2))
    except TypeError:
        s1_enc = s1.decode('utf-8')
        s2_enc = s2.decode('utf-8')
        xored = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s1_enc, s2_enc))
    if bytes_out:
        return xored.encode('utf-8')
    else:
        return xored


def xor_bytes(b1, b2):
    xor = b''
    for x, y in zip(b1, b2):
        xor += bytes([x ^ y])
    return xor


def hex2dec(str_hex: str, bytes_out: bool = False) -> str:
    """Convert from hexadecimal to decimal."""
    res = ''.join([chr(int(''.join(c), 16)) for c in zip(str_hex[0::2], str_hex[1::2])])
    if bytes_out:
        return res.encode('utf-8')
    else:
        return res


def dec2hex(string_dec: str):
    return hexlify(string_dec.encode('utf-8')).decode('utf-8')


def pad_pkcs(text: bytes, length: int) -> bytes:
    pad = (length - (len(text) % length)) % length
    if len(text) != 0:
        return text + bytes([pad] * pad)
    else:
        return bytes([length] * length)


def unpad_pkcs(text: bytes, length: int) -> bytes:
    if len(text) % length == 0:
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


def matrix_to_bytes(state: list, dimension: int = 4) -> bytes:
    """Returns byte string from NxN byte matrix"""
    state_byte = b''
    for i in range(4):
        for j in range(4):
            state_byte += bytes([state[j][i]])
    return state_byte


def xor_states(state1: list, state2: list) -> list:
    """Xor two 4x4 matrix states"""
    result = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            result[i].append(state1[i][j] ^ state2[i][j])
    return result


def string_to_matrix_states(string: str) -> list:
    """Converts text string in an array of 4x4 bytes matrix"""
    # blocks of 16 bytes
    blocks = [string[i:i + 16] for i in range(0, len(string), 16)]
    # ensure fixed size blocks by adding padding (PKCS)
    # blocks must be <class 'bytes'>
    if len(blocks):
        blocks[len(blocks) - 1] = pad_pkcs(blocks[len(blocks) - 1], 16)
    states = []
    for block in blocks:
        state = [[], [], [], []]  # each state is a 4x4 bytes matrix
        for i in range(4):
            for j in range(4):
                state[i].append(block[(j * 4) + i])
        states.append(state)
    return states


def divide_in_blocks(long_string: str, block_length: int) -> list:
    """Return a list of 16 bits block"""
    # blocks = [long_string[j:j + 16] for j in range(0, len(long_string), 16)]
    blocks = []
    for i in range(0, len(long_string), block_length):
        blocks.append(long_string[i:i + block_length])
    return blocks
