from challenge03 import xor_decrypt

# One of the 60-character strings in the file has been encrypted by single-character XOR.


if __name__ == '__main__':

    f = open('sources/4.txt', 'r')

    file_results = []
    for line in f:
        result = xor_decrypt(line.strip('\n'))
        file_results.append(result)
    sorted_score = sorted(file_results, key=lambda tup: tup[0])[0]
    print('(key, score, decrypted_string, input_hex)')
    print(sorted_score)
    print('cipher key:', sorted_score[0], '(' + chr(sorted_score[0]) + ')')
