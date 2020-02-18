import re
from binascii import a2b_base64
from collections import defaultdict
from operator import itemgetter

from challenge18 import aes128_ctr_cipher
from utils import pad_pkcs, generate_aes_key, xor_bytes


def encrypt_data():
    key = generate_aes_key()
    nonce = bytes([0]) * 8  # nonce forced to 0
    f = open('sources/20.txt', 'r')
    cipher_texts = []
    n = 0
    for line in f:
        # sprint(n, a2b_base64(line), len(a2b_base64(line)))
        cipher_text = aes128_ctr_cipher(a2b_base64(line), nonce, key)
        cipher_texts.append(cipher_text)
        n += 1
    # Return an array of cipher_texts encrypted with the same key and nonce in CTR mode
    return cipher_texts


def guess_byte_score(byte_array, mode):
    """
    if mode == True, reward uppercase
    """
    english_uppercase = "ETAOINSHRDLU "
    english_lowercase = "etaoinshrdlu "
    punctuation = " ,.:;'"
    score = [-1] * 256
    score_dict = {}
    for i in range(256):
        for byte in byte_array:
            xor = i ^ byte
            for a in english_uppercase:  # more frequent characters in english
                if ord(a) == xor:
                    score[i] += 20
            for l in english_lowercase:  # more frequent characters in english
                if ord(l) == xor:
                    score[i] += 20
            for p in punctuation:  # punctuation
                if ord(p) == xor:
                    score[i] += 5
            for b in range(16, 31):  # non legible characters, possible padding excluded
                if b == xor:
                    score[i] -= 50
            for c in range(65, 90):  # uppercase letter
                if c == xor:
                    score[i] += 2
                    if mode:
                        score[i] += 50
            for d in range(97, 122):  # lowercase letter
                if d == xor:
                    score[i] += 2
        score_dict[i] = score[i]
    return score_dict


def calculate_keystream(ctr):
    """
    From a list of cipher text guess the best keystream that returns more readable text
    We assume that all of encryptions have been with the same key and nonce.
    """
    # Append cipher_texts with 'refined' flag marked as false. 40 the first iteration.
    cipher_texts = []
    for c in range(len(ctr)):
        if not ctr[c]['refined']:
            cipher_texts.append(ctr[c]['cipher'])

    # First of all we need to convert the list into a dict of lists of every char in all cipher_text
    cipher_bytes = defaultdict(list)
    for cipher_text in cipher_texts:  # 40 times first time
        for index, cipher_char in enumerate(cipher_text):  # 32 or 48 times, due to padding (texts have different size)
            cipher_bytes[index].append(cipher_char)

    # Guess keystream
    keystream = b''
    for i in range(len(cipher_bytes)):  # Iterate all the first characters, after the seconds, and the following
        if i == 0:  # Reward uppercase for the first letter
            score_dict = guess_byte_score(cipher_bytes[i], True)
        else:
            score_dict = guess_byte_score(cipher_bytes[i], False)
        sorted_score = sorted(score_dict.items(), key=itemgetter(1),
                              reverse=True)  # [(key, score), ... ]
        best_score = sorted_score[0][0]
        keystream += bytes([best_score])
    return keystream


def refine_block(ctr, block):
    """
    Look for padding and remove it, marking the text as refined.
    Block number start by 0.
    """
    for c in range(len(ctr)):
        if not ctr[c]['refined']:
            plain_text_block = ctr[c]['plain'][block * 16:(block + 1) * 16]  # Let's focus on second block
            posible_pad = re.findall(b'[\x01-\x15]+', plain_text_block)  # Look for pad bytes
            if posible_pad:
                position_pad = plain_text_block.find(posible_pad[-1])
                if len(plain_text_block[position_pad:]) == posible_pad[0][0]:  # possible pad match length
                    plain_text_block = plain_text_block[:position_pad]  # delete pad
                    ctr[c]['plain'] = ctr[c]['plain'][:block * 16] + plain_text_block + ctr[c]['plain'][
                                                                                        (block + 1) * 16:]
                    ctr[c]['refined'] = True
                    # print(ctr[c]['plain'])  # strings fully decrypted
    return ctr


def count_not_refined(ctr):
    refined = 0
    for t in ctr:
        if t['refined']:
            refined += 1
    return len(ctr) - refined


def truncate(ctr, size):
    for t in ctr:
        t['cipher'] = t['cipher'][:size]
        t['plain'] = t['plain'][:size]
    return ctr


if __name__ == '__main__':

    # Break fixed-nonce CTR mode using substitutions

    # Data encrypted with random key
    cipher_texts = encrypt_data()

    # CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
    # CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE

    # build data structure
    ctr_substitution = [dict() for x in range(len(cipher_texts))]  # array of dicts
    smallest = len(cipher_texts[0])
    for index in range(len(cipher_texts)):
        ctr_substitution[index]['cipher'] = cipher_texts[index]
        ctr_substitution[index]['plain'] = b''
        ctr_substitution[index]['refined'] = False
        if len(ctr_substitution[index]['cipher']) < smallest:
            smallest = len(ctr_substitution[index]['cipher'])
    print("smallest text:", smallest)

    # Truncate texts to a common length.
    print("Truncate")
    ctr_truncated = truncate(ctr_substitution, smallest)

    print("First attempt. Calculate the keystream that returns more readable text.")
    key_stream = calculate_keystream(ctr_truncated)
    print("Keystream 1:", key_stream)
    # decrypt using key stream
    for i in range(len(ctr_truncated)):
        if not ctr_truncated[i]['refined']:
            ctr_truncated[i]['plain'] = xor_bytes(ctr_truncated[i]['cipher'], key_stream)
        print(i, ctr_truncated[i]['plain'], len(ctr_truncated[i]['plain']),
              "refined:", ctr_truncated[i]['refined'])
    print("\n", count_not_refined(ctr_truncated), "texts to be refined")

    # The beginning of sentences can be read, but some padding is detected.
    ctr_truncated = refine_block(ctr_truncated, int(smallest / 16) - 1)  # last block

    print("\nSecond attempt: Refined")
    for i in range(len(ctr_truncated)):
        if not ctr_truncated[i]['refined']:
            ctr_truncated[i]['plain'] = xor_bytes(ctr_truncated[i]['cipher'], key_stream)
            ctr_truncated[i]['refined'] = True
        print(i, ctr_truncated[i]['plain'])

