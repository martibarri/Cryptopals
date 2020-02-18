from huepy import good, info

from utils import divide_in_blocks, read_data


if __name__ == '__main__':

    """Detect AES in ECB mode"""

    encrypted_data_hex = read_data('8', out_multiline=True)
    scores = []

    for encrypted_line_hex in encrypted_data_hex:
        encrypted_line_blocks = divide_in_blocks(encrypted_line_hex, 16)
        score = len(encrypted_line_blocks) - len(set(encrypted_line_blocks))
        scores.append(score)

    max_score = max(scores)
    positions = [i for i, j in enumerate(scores) if j == max_score]
    # note that in fact only one score != 0

    for i in range(len(positions)):
        ecb = divide_in_blocks(encrypted_data_hex[positions[i]], 16)
        print(info("Ciphertext encrypted with AES-ECB:"))
        for block_slice in ecb:
            print(block_slice)
        print(good(f"Line location: {positions[i]}"))
        print(good(f"Number of repeated blocks: {scores[positions[i]]}"))

    # the same 16 byte plaintext block will always produce the same 16 byte ciphertext
