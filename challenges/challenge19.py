import re
from binascii import a2b_base64
from collections import defaultdict
from operator import itemgetter

from challenge18 import aes128_ctr_cipher
from utils import pad_pkcs, generate_aes_key, xor_bytes


def encrypt_data():
    key = generate_aes_key()
    nonce = bytes([0]) * 8  # nonce forced to 0
    f = open('sources/19.txt', 'r')
    cipher_texts = []
    n = 0
    for line in f:
        # print(n, a2b_base64(line), len(a2b_base64(line)))
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


if __name__ == '__main__':

    # Break fixed-nonce CTR mode using substitutions

    # Data encrypted with random key
    cipher_texts = encrypt_data()

    # CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
    # CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE

    # build data structure
    ctr_substitution = [dict() for x in range(len(cipher_texts))]  # array of dicts
    for index in range(len(cipher_texts)):
        ctr_substitution[index]['cipher'] = cipher_texts[index]
        ctr_substitution[index]['plain'] = b''
        ctr_substitution[index]['refined'] = False

    print("First attempt. Calculate the keystream that returns more readable text.")
    key_stream = calculate_keystream(ctr_substitution)
    print("Keystream 1:", key_stream)
    # decrypt using key stream
    for i in range(len(ctr_substitution)):
        if not ctr_substitution[i]['refined']:
            ctr_substitution[i]['plain'] = xor_bytes(ctr_substitution[i]['cipher'], key_stream)
        print(i, ctr_substitution[i]['plain'], len(ctr_substitution[i]['plain']),
              "refined:", ctr_substitution[i]['refined'])
    print("\n", count_not_refined(ctr_substitution), "texts to be refined")

    # At this point, the beginning of sentences can be read, but the end is definitely not readable.
    # We can conclude that the first block is correctly, and the followings are deviated due the padding chars.
    # Let's try to refine our results, starting by block number two:
    ctr_substitution = refine_block(ctr_substitution, 1)  # 1 is the block number two

    key_stream_refined = b''
    for i in range(len(ctr_substitution)):
        if ctr_substitution[i]['refined']:
            pad_plain = pad_pkcs(ctr_substitution[i]['plain'], 16)  # pad any refined text correctly
            # plain xor cipher = keystream
            key_stream_refined = xor_bytes(pad_plain, ctr_substitution[i]['cipher'])  # Calculate keystream again
            break

    # The keystream calculated from refined only sizes two blocks.
    # For the last block we use the keystream calculated before
    key_stream = key_stream_refined[:32] + key_stream[32:]

    # decrypt using the new keystream
    print("\nSecond attempt using the new keystream:")
    print("Keystream 2:", key_stream)
    for i in range(len(ctr_substitution)):
        if not ctr_substitution[i]['refined']:
            ctr_substitution[i]['plain'] = xor_bytes(ctr_substitution[i]['cipher'], key_stream)
        print(i, ctr_substitution[i]['plain'], len(ctr_substitution[i]['plain']),
              "refined:", ctr_substitution[i]['refined'])
    print("\n", count_not_refined(ctr_substitution), "texts to be refined")

    # Let's refine again the second block without short texts that deviate the refination.
    # All the texts should be unpadded now.
    ctr_substitution = refine_block(ctr_substitution, 1)

    # The keystream would not have had to change now, but we recalculate it again to be sure.
    key_stream_refined = b''
    for i in range(len(ctr_substitution)):
        if ctr_substitution[i]['refined']:
            pad_plain = pad_pkcs(ctr_substitution[i]['plain'], 16)
            # plain xor cipher = keystream
            key_stream_refined = xor_bytes(pad_plain, ctr_substitution[i]['cipher'])
            break

    # At this point, we can assume that the first and the second blocks of key_stream are correct
    key_stream = key_stream[:16] + key_stream_refined[16:32] + key_stream[32:]

    # decrypt using the new key stream
    print("\nThird attempt:")
    print("Keystream 3:", key_stream)
    for i in range(len(ctr_substitution)):
        if not ctr_substitution[i]['refined']:
            ctr_substitution[i]['plain'] = xor_bytes(ctr_substitution[i]['cipher'], key_stream)
        print(i, ctr_substitution[i]['plain'], len(ctr_substitution[i]['plain']),
              "refined:", ctr_substitution[i]['refined'])
    print("\n", count_not_refined(ctr_substitution), "texts to be refined")

    # Looking the results, the texts 6, 25 and 29 seems to be correct, so we mark them as refined manually.
    # They have no padding because their size is exactly 32.
    ctr_substitution[6]['refined'] = True
    ctr_substitution[25]['refined'] = True
    ctr_substitution[29]['refined'] = True

    print("\nFourth attempt (manually refined):")
    print("Keystream 4:", key_stream)
    for i in range(len(ctr_substitution)):
        if not ctr_substitution[i]['refined']:
            ctr_substitution[i]['plain'] = xor_bytes(ctr_substitution[i]['cipher'], key_stream)
        print(i, ctr_substitution[i]['plain'], len(ctr_substitution[i]['plain']),
              "refined:", ctr_substitution[i]['refined'])
    print("\n", count_not_refined(ctr_substitution), "texts to be refined")

    # The remaining three texts will be more difficult to decrypt, because the 3rd block of keystream only appears on
    # they.

    # This process is suboptimal, we are not able to find the last block of key stream with only three ciphertexts with
    # different length.
