from challenge03 import xor_decrypt, read_data
from huepy import good, info, bold


if __name__ == '__main__':

    # One of the 60-character strings in the file
    # has been encrypted by single-character XOR.

    encrypted_data = read_data('4', out_multiline=True)
    decrypted_data = []
    for line in encrypted_data:
        decrypted_data.append(xor_decrypt(line))

    sorted_score = sorted(decrypted_data, key=lambda tup: tup[0])[0]

    print(info(f'input_hex: {sorted_score[3]}'))
    print(good(f'score: {sorted_score[1]}'))
    print(good(f'cipher key: {sorted_score[0]} ( {chr(sorted_score[0])} )'))
    print(bold(good(f'decrypted_string: {sorted_score[2].encode()}')))
