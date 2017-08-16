import sys
sys.path.insert(0, '../Set1')
from challenge07 import aes128_RoundBlock, aes128_InvRoundBlock, XorStates, matrix_to_hex, string_to_matrix_states
from binascii import hexlify, unhexlify, a2b_base64

# Implement CBC mode

def aes128_cbc_decrypt(ciphertext_hex, iv, key):
	iv_matrix = string_to_matrix_states(iv)
	states = string_to_matrix_states(ciphertext_hex)
	decrypted_hex = ""
	for index, state in enumerate(states):
		if index == 0:
			d = XorStates(aes128_InvRoundBlock(state, key), iv_matrix)
		else:
			d = XorStates(aes128_InvRoundBlock(state, key), states[index-1])
		decrypted_hex += matrix_to_hex(d)
	return decrypted_hex

def aes128_cbc_encrypt(plaintext_hex, iv, key):
	iv_matrix = string_to_matrix_states(iv)
	states = string_to_matrix_states(plaintext_hex)
	encrypted_hex = ""
	previous_ciphertext_state = [ [], [], [], [] ]
	for index, state in enumerate(states):
		if index == 0:
			e = aes128_RoundBlock(XorStates(state, iv_matrix), key)
		else:
			e = aes128_RoundBlock(XorStates(state, previous_ciphertext_state), key)
		previous_ciphertext_state = e
		encrypted_hex += matrix_to_hex(e)
	return encrypted_hex


if __name__ == '__main__':

	key = "YELLOW SUBMARINE"
	iv = "\x00"*16

	f = open('../sources/10.txt', 'r')
	encrypted_data_base64 = ""
	for line in f:
		encrypted_data_base64 += line.strip('\n')
	encrypted_data_hex = hexlify(a2b_base64(encrypted_data_base64))

	decrypted_hex = aes128_cbc_decrypt(encrypted_data_hex, hexlify(iv.encode('utf-8')), key)
	encrypted_hex = aes128_cbc_encrypt(decrypted_hex, hexlify(iv.encode('utf-8')), key)

	if encrypted_hex == encrypted_data_hex.decode("utf-8"):
		print("---------- AES128 CBC MODE WORKS CORRECTLY ----------")
	else:
		print("---------- ERROR! ----------")

	print(unhexlify(decrypted_hex.encode('utf-8')).decode('utf-8'))
