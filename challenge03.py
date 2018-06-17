import operator


def xor_cipher(string_hex):
    string_dec = (''.join([chr(int(''.join(c), 16)) for c in zip(string_hex[0::2], string_hex[1::2])]))
    xor_array = [""] * 256
    for i in range(0, 256):
        xor_tmp = ""
        for x in string_dec:
            xor_tmp += chr(ord(x) ^ i)
            xor_array[i] = xor_tmp
    return xor_array


def xor_cipher_score(xor_array):
    english = "ETAOINSHRDLU"
    english += english.lower()
    score = [-1] * 256
    xor_dict = {}
    for i in range(0, 256):
        # print(i, chr(i), xor_array[i])
        for a in english:  # more frequent characters in english
            score[i] += xor_array[i].count(a) * 2
        for b in range(0, 31):  # non legible characters
            score[i] -= xor_array[i].count(chr(b)) * 50
        score[i] -= xor_array[i].count(chr(127)) * 50  # DEL
        score[i] += xor_array[i].count(chr(32)) * 20  # space
        for c in range(65, 90):  # uppercase letter
            score[i] += xor_array[i].count(chr(c)) * 3
        for d in range(97, 122):  # lowercase letter
            score[i] += xor_array[i].count(chr(d)) * 3
        # for e in range(128, 256):  # Extended ASCII Table
        #   score[i] -= xor_array[i].count(chr(e)) * 10
        xor_dict[i] = score[i]
    return xor_dict


def xor_result(xor_score_dict, cipher_array, string_hex):
    sorted_score = sorted(xor_score_dict.items(), key=operator.itemgetter(1),
                          reverse=True)  # [(88, 224), (95, 125), ... ] (key, score)
    result_array = [] * 255
    for j in range(0, 256):
        result_array.append((sorted_score[j][0], sorted_score[j][1], cipher_array[sorted_score[j][0]], string_hex))
        # [(key, score, string_decrypted, input_string), (), ()...] ordered by score
    return result_array


def xor_decrypt(string_hex):
    xor_array = xor_cipher(string_hex)  # cipher by every char
    xor_score = xor_cipher_score(xor_array)  # score
    result = xor_result(xor_score, xor_array, string_hex)  # order by score
    # debug results:
    # print('(key, score, string_decrypted)')
    # for j in range(0, 10):
    #   print(result[j])
    final_result = result[0]  # first one with better score
    return final_result


if __name__ == '__main__':
    # The hex encoded string has been XOR'd against a single character. Find the key, decrypt the message.
    input_string_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    final_result = xor_decrypt(input_string_hex)
    print('final result:')
    print('key:', final_result[0], '(' + chr(final_result[0]) + ')')
    print('score:', final_result[1])
    print('decrypted string:', final_result[2])
