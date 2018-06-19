from operator import itemgetter
from base64 import b64decode
from utils import dec2hex
from challenge03 import xor_decrypt


def hamming_distance(s1, s2):
    s1_bin = ''.join(format(ord(x), '08b') for x in s1)
    s2_bin = ''.join(format(ord(x), '08b') for x in s2)
    diffs = 0
    for ch1, ch2 in zip(s1_bin, s2_bin):
        if ch1 != ch2:
            diffs += 1
    return diffs


if __name__ == '__main__':

    f = open('sources/6.txt', 'r')
    encrypted_data_base64 = ""
    for line in f:
        encrypted_data_base64 += line.strip('\n')
    encrypted_data_ascii = b64decode(encrypted_data_base64).decode('utf-8')

    KEYSIZE_candidates = []
    for KEYSIZE in range(2, 41):
        differing_total = 0
        for k in range(16):
            differing = float(hamming_distance(encrypted_data_ascii[KEYSIZE * (k * 2):KEYSIZE * (k * 2 + 1)],
                                               encrypted_data_ascii[KEYSIZE * (k * 2 + 1):KEYSIZE * (k * 2 + 2)]))
            differing_total += differing
        value = (differing_total / 16) / KEYSIZE
        KEYSIZE_candidates.append({'KEYSIZE': KEYSIZE, 'value': value})

    KEYSIZE_candidates = sorted(KEYSIZE_candidates, key=itemgetter('value'))

    for i in range(1):
        ks = KEYSIZE_candidates[i]['KEYSIZE']
        print("-" * 100)
        print("KEYSIZE:", ks)
        blocks = []
        tblocks = [""] * ks
        key = ""
        decrypted = [""] * len(encrypted_data_ascii)
        for j in range(int(len(encrypted_data_ascii) / ks)):
            blocks.append(encrypted_data_ascii[ks * j:ks * (j + 1)])  # break ciphertext into blocks
        for k in range(ks):
            for l in range(len(blocks)):
                tblocks[k] += blocks[l][k]  # transpose blocks
            result = xor_decrypt(dec2hex(tblocks[k]))
            subkey = result[0]
            tdecrypted = result[2]
            key += chr(subkey)
            for m in range(len(tdecrypted)):
                decrypted[k + m * ks] = tdecrypted[m]
        print("KEY:", key)
        print("OUTPUT:", ''.join(decrypted))
