from gf256 import GF256LT
from binascii import hexlify, unhexlify, a2b_base64

from utils import dec2hex, base642hex, pad_pkcs

# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
# openssl enc -aes-128-ecb -K 59454c4c4f57205355424d4152494e45 -base64 -d -in 7.txt -out 7_d.txt
# AES 128
# 10 cycles of repetition
# Nr = 10, Nb = 4, Nk = 4

SBox = (0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16)

invSBox = (0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
           0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
           0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
           0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
           0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
           0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
           0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
           0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
           0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
           0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
           0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
           0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
           0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
           0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
           0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
           0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d)


def matrix_to_hex(state):
    """Returns hex string from 4x4 byte matrix"""
    state_hex = ""
    for i in range(4):
        for j in range(4):
            state_hex += format(state[j][i], '02x')
    return state_hex


def RCON(i):
    Rcon = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54]
    return [Rcon[int(i - 1)], 0, 0, 0]


def RotWord(w):
    rot = (w[1:] + w[:1])
    return rot


def SubWord(w):
    subwords = []
    for i in range(4):
        hex_byte = "{0:#0{1}x}".format(w[i], 4)
        x = int(hex_byte[2], 16)
        y = int(hex_byte[3], 16)
        subwords.append(SBox[y + (x * 16)])
    return subwords


def InvKeyExpansion(key_hex):
    key_byte = bytearray.fromhex(key_hex)
    w = []
    for i in range(0, 4):
        w.append(key_byte[i * 4:(i + 1) * 4])
    for j in range(4, 44):
        tmp = w[j - 1]
        if j % 4 == 0:
            tmp = bytearray(SubWord(RotWord(tmp))[k] ^ RCON(j / 4)[k] for k in range(0, 4))
        new_w = bytearray(w[j - 4][k] ^ tmp[k] for k in range(0, 4))
        w.append(new_w)  # w[j] = w[j-4] ^ tmp
    keys = []
    for a in range(int(len(w) / 4)):
        key = [[], [], [], []]  # 4x4 bytes matrix
        for b in range(4):
            for c in range(4):
                key[b].append(w[(a * 4) + c][b])
        if a != 10 and a != 0:
            key = InvMixColumns(key)
        keys.append(key)
    return keys  # 11 keys 4x4 bytes matrix


def KeyExpansion(key_hex):
    key_byte = bytearray.fromhex(key_hex)
    w = []
    for i in range(0, 4):
        w.append(key_byte[i * 4:(i + 1) * 4])
    for j in range(4, 44):
        tmp = w[j - 1]
        if j % 4 == 0:
            tmp = bytearray(SubWord(RotWord(tmp))[k] ^ RCON(j / 4)[k] for k in range(0, 4))
        new_w = bytearray(w[j - 4][k] ^ tmp[k] for k in range(0, 4))
        w.append(new_w)  # w[j] = w[j-4] ^ tmp
    keys = []
    for a in range(int(len(w) / 4)):
        key = [[], [], [], []]  # 4x4 bytes matrix
        for b in range(4):
            for c in range(4):
                key[b].append(w[(a * 4) + c][b])
        keys.append(key)
    return keys  # 11 keys 4x4 bytes matrix


def SubBytes(state):  # https://en.wikipedia.org/wiki/Rijndael_S-box
    new_state = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            hex_byte = "{0:#0{1}x}".format(state[i][j], 4)
            x = int(hex_byte[2], 16)
            y = int(hex_byte[3], 16)
            new_state[i].append(SBox[y + (x * 16)])
    return new_state


def InvSubBytes(state):  # https://en.wikipedia.org/wiki/Rijndael_S-box
    new_state = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            hex_byte = "{0:#0{1}x}".format(state[i][j], 4)
            x = int(hex_byte[2], 16)
            y = int(hex_byte[3], 16)
            new_state[i].append(invSBox[y + (x * 16)])
    return new_state


def ShiftRows(state):
    for i in range(1, 4):
        a = state[i][i:4]
        a.extend(state[i][0:i])
        state[i] = a
    return state


def InvShiftRows(state):
    for i in range(1, 4):
        a = state[i][4 - i:4]
        a.extend(state[i][0:4 - i])
        state[i] = a
    return state


def MixColumns(state):
    result = [[], [], [], []]
    mix_columns = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    for i in range(4):
        for j in range(4):
            mix = 0
            for k in range(4):
                mix = (mix ^ int(GF256LT(state[k][j]) * GF256LT(mix_columns[i][k])))
            result[i].append(mix)
    return result


def InvMixColumns(state):
    result = [[], [], [], []]
    mix_columns = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
    for i in range(4):
        for j in range(4):
            mix = 0
            for k in range(4):
                mix = (mix ^ int(GF256LT(state[k][j]) * GF256LT(mix_columns[i][k])))
            result[i].append(mix)
    return result


def XorStates(state1, state2):
    result = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            result[i].append(state1[i][j] ^ state2[i][j])
    return result


def aes128_InvRoundBlock(state, key_hex):
    """
    AES128 Block Cipher Decryption
    key must be Hexadecimal
    state must be a 4x4 byte matrix
    """
    key_expanded = InvKeyExpansion(key_hex)  # 44 keys of 4 bytes
    Round = XorStates(state, key_expanded[len(key_expanded) - 1])
    for i in range(1, len(key_expanded) - 1):
        Round = InvSubBytes(Round)
        Round = InvShiftRows(Round)
        Round = InvMixColumns(Round)
        Round = XorStates(Round, key_expanded[len(key_expanded) - 1 - i])
    Round = InvSubBytes(Round)
    Round = InvShiftRows(Round)
    Round = XorStates(Round, key_expanded[0])
    return Round


def aes128_RoundBlock(state, key_hex):
    """
    AES128 Block Cipher Encryption
    key must be Hexadecimal
    state must be a 4x4 byte matrix
    """
    key_expanded = KeyExpansion(key_hex)  # 44 keys of 4 bytes
    Round = XorStates(state, key_expanded[0])
    for i in range(1, len(key_expanded) - 1):
        Round = SubBytes(Round)
        Round = ShiftRows(Round)
        Round = MixColumns(Round)
        Round = XorStates(Round, key_expanded[i])
    Round = SubBytes(Round)
    Round = ShiftRows(Round)
    Round = XorStates(Round, key_expanded[len(key_expanded) - 1])
    return Round


def string_to_matrix_states(string):
    """Converts text string in an array of 4x4 bytes matrix"""
    blocks = [unhexlify(string[i:i + 32]) for i in range(0, len(string), 32)]  # blocks of 16 bytes
    # ensure fixed size blocks by adding padding (PKCS)
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


def aes128_ecb_decrypt(ciphertext_hex, key_hex):
    states = string_to_matrix_states(ciphertext_hex)
    decrypted_hex = ""
    for state in states:
        d = matrix_to_hex(aes128_InvRoundBlock(state, key_hex))
        decrypted_hex += d
    return decrypted_hex


def aes128_ecb_encrypt(plain_text_hex, key_hex):
    states = string_to_matrix_states(plain_text_hex)
    encrypted_hex = ""
    for state in states:
        d = matrix_to_hex(aes128_RoundBlock(state, key_hex))
        encrypted_hex += d
    return encrypted_hex


if __name__ == '__main__':

    key = "YELLOW SUBMARINE"
    key_hex = dec2hex(key)

    f = open('sources/7.txt', 'r')
    encrypted_data_base64 = ""
    for line in f:
        encrypted_data_base64 += line.strip('\n')
    encrypted_data_hex = base642hex(encrypted_data_base64)

    decrypted_hex = aes128_ecb_decrypt(encrypted_data_hex, key_hex)
    encrypted_hex = aes128_ecb_encrypt(decrypted_hex, key_hex)

    if encrypted_hex == encrypted_data_hex.decode("utf-8"):
        print("---------- AES128 ECB MODE WORKS CORRECTLY ----------")
    else:
        print("---------- ERROR! ----------")

    print(unhexlify(decrypted_hex.encode('utf-8')).decode('utf-8'))
