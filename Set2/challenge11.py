from sys import path
path.insert(0, '../Set1')
from challenge07 import aes128_ecb_decrypt, aes128_ecb_encrypt
from challenge10 import aes128_cbc_encrypt
from binascii import hexlify, unhexlify
from os import urandom
from random import randint

def generate_aes_key():
	return urandom(16)

def append_random_bytes(plain_text):
	"""append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext."""
	return urandom(randint(5,10)) + plain_text.encode('utf-8') + urandom(randint(5,10))

def encryption_oracle(plain_text):
	plain_text_ext = append_random_bytes(plain_text)
	plain_text_hex = hexlify(plain_text_ext).decode('utf-8')
	
	key = generate_aes_key()
	key_hex = hexlify(key).decode('utf-8')
	if randint(0,1):
		cipher_text_hex = aes128_ecb_encrypt(plain_text_hex, key_hex)
		#print("ECB")
	else:
		iv = generate_aes_key()
		iv_hex = hexlify(iv).decode('utf-8')
		cipher_text_hex = aes128_cbc_encrypt(plain_text_hex, iv_hex, key_hex)
		#print("CBC")

	return unhexlify(cipher_text_hex.encode('utf-8'))


if __name__ == '__main__':
	'''
	This function detect if ECB of CBC mode is used
	The problem with ECB is that it is stateless and deterministic; 
	the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
	Due that, if we generate always the same data, the ecb mode will be always output
	the same ciphertext (except the random bytes added)
	'''

	data = "\x00"*200
	encrypted_data = encryption_oracle(data)
	encrypted_data_hex = hexlify(encrypted_data).decode('utf-8')

	blocks = [unhexlify(encrypted_data_hex[i:i + 32]) for i in range(0, len(encrypted_data_hex), 32)]
	numer_of_repeated_blocks = len(blocks) - len(set(blocks))
	print("Number of repeated blocks:", numer_of_repeated_blocks)
	if numer_of_repeated_blocks:
		print("The cipher is using ECB mode")
	else:
		print("The cipher is using CBC mode")
