import sys
sys.path.insert(0, '../Set1')
from challenge07 import aes128_InvRoundBlock, XorStates, matrix_to_hex
from binascii import hexlify, unhexlify, a2b_base64

# Implement CBC mode

def aes128_cbc_decrypt(ciphertext_hex, iv, key):

	iv_matrix = [ [], [], [], [] ]
	for i in range(4):
			for j in range(4):
				iv_matrix[i].append(iv[i*4+j])
	
	blocks = [unhexlify(ciphertext_hex[i:i + 32]) for i in range(0, len(ciphertext_hex), 32)]
	states = []
	for block in blocks: # per cada block de 16 bytes
		state = [ [], [], [], [] ] # state es una matriu de 4x4 bytes
		for i in range(4):
			for j in range(4):
				state[i].append(block[(j*4)+i])
		states.append(state)

	decrypted_hex = ""
	for index, state in enumerate(states):
		if index == 0:
			d = XorStates(aes128_InvRoundBlock(state, key), iv_matrix)
		else:
			d = XorStates(aes128_InvRoundBlock(state, key), states[index-1])
		decrypted_hex += matrix_to_hex(d)
	return decrypted_hex


if __name__ == '__main__':

	key = "YELLOW SUBMARINE"
	iv = "\x00"*32

	f = open('../sources/10.txt', 'r')
	encrypted_data_base64 = ""
	for line in f:
		encrypted_data_base64 += line.strip('\n')
	encrypted_data_hex = hexlify(a2b_base64(encrypted_data_base64))

	decrypted_hex = aes128_cbc_decrypt(encrypted_data_hex, iv.encode('utf-8'), key)
	print(unhexlify(decrypted_hex.encode('utf-8')).decode('utf-8'))
