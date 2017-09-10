from sys import path
path.insert(0, '../Set1')
from challenge07 import aes128_ecb_encrypt
from challenge09 import pad_PKCS
from challenge11 import generate_aes_key
from challenge12 import discover_block_size, detect_ecb_mode
from binascii import hexlify, unhexlify
from base64 import b64decode
from os import urandom
from random import randint

class encryption_oracle_ecb():

	def __init__(self, data):
		self.key = generate_aes_key()
		self.data = data
		self.random_bytes = urandom(randint(0,15))
	
	def encrypt(self, plain_text):
		key_hex = hexlify(self.key).decode('utf-8')
		# the difference between this challenge and challenge12 are the random bytes
		plain_text_pad = pad_PKCS(self.random_bytes + plain_text + b64decode(self.data), 16)
		plain_text_hex = hexlify(plain_text_pad).decode('utf-8')
		cipher_text_hex = aes128_ecb_encrypt(plain_text_hex, key_hex)
		return unhexlify(cipher_text_hex.encode('utf-8'))

def find_byte(encryption_oracle, block_size, known_bytes, random_bytes_length):
	prefix_length = block_size - ((1 + len(known_bytes)) % block_size) 
	prefix = bytes([0]*prefix_length)
	test_length = prefix_length + len(known_bytes) + 1
	altered_prefix = bytes([0]*(block_size - random_bytes_length)) + prefix
	real_ciphertext = encryption_oracle.encrypt(altered_prefix)
	clean_real_ciphertext = real_ciphertext[block_size:] # avoid random bytes
	for i in range(256):
		test_ciphertext = encryption_oracle.encrypt(altered_prefix + known_bytes + bytes([i]))
		clean_test_ciphertext = test_ciphertext[block_size:]
		if clean_test_ciphertext[:test_length] == clean_real_ciphertext[:test_length]:
			return bytes([i])
	return b''


def detect_random_bytes(encryption_oracle, block_size):
	'''
	If random prefix max length is 16 bytes, feeding the oracle with known data
	with double block size, we will have a cipher block of known data
	example: random_bytes = "asd" (3)
	asdAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAA*************
	asdAAAAAAAAAAAAA AAAAAAAAAAAAAAAA -> 16*2 - 16+13 = 32 - 29 = 3
	example: random_bytes = "fsdfjkj3rfn34r" (14)
	fsdfjkj3rfn34rAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAA**
	fsdfjkj3rfn34rAA AAAAAAAAAAAAAAAA -> 16*2 - 16+2 = 32 - 18 = 14
	'''	
	max_test_data = b'A'*2*block_size
	encrypted_max_test_data = encryption_oracle.encrypt(max_test_data)
	known_ciphertext = encrypted_max_test_data[block_size:2*block_size]
	for i in range(block_size, 2*block_size):
		test_data = b'A'*i
		encrypted_test_data = encryption_oracle.encrypt(test_data)
		if encrypted_test_data[block_size:2*block_size] == known_ciphertext:
			random_bytes_length = 2*block_size - i
			return random_bytes_length
	return 0


if __name__ == '__main__':

	data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	encryption_oracle = encryption_oracle_ecb(data)

	block_size = discover_block_size(encryption_oracle)
	print("Block size:", block_size, "bytes")
	if not detect_ecb_mode(encryption_oracle):
		print("The cipher is NOT using ECB mode")
	else:
		print("The cipher is using ECB mode")
		random_bytes_length = detect_random_bytes(encryption_oracle, block_size)
		decrypted_data = b''
		data_length = len(encryption_oracle.encrypt(b''))
		for i in range(data_length):
			next_byte = find_byte(encryption_oracle, block_size, decrypted_data, random_bytes_length)
			decrypted_data += next_byte
			#print(decrypted_data)
			print("Decrypting: " + "{:4.2f}".format(100*(i+1)/data_length) + "%", end='\r')
		print("Decryption complete!")
		print(decrypted_data.decode('utf-8'))