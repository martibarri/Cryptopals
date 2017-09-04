from sys import path
path.insert(0, '../Set1')
from challenge07 import aes128_ecb_decrypt, aes128_ecb_encrypt
from challenge09 import pad_PKCS
from challenge10 import aes128_cbc_encrypt
from challenge11 import append_random_bytes, generate_aes_key
from random import randint
from binascii import hexlify, unhexlify
from base64 import b64decode

class encryption_oracle_ecb():

	def __init__(self, data):
		self.key = generate_aes_key()
		self.data = data
	
	def encrypt(self, plain_text):
		key_hex = hexlify(self.key).decode('utf-8')
		plain_text_pad = pad_PKCS(plain_text + b64decode(self.data), 16)
		plain_text_hex = hexlify(plain_text_pad).decode('utf-8')
		cipher_text_hex = aes128_ecb_encrypt(plain_text_hex, key_hex)
		return unhexlify(cipher_text_hex.encode('utf-8'))

def discover_block_size(encryption_oracle):
	'''
	Discover the block size of the cipher
	Note: len(hex_string) = 2 * len(byte_string)
	'''
	test_data = b''
	initial_size = len(encryption_oracle.encrypt(test_data))
	test_size = initial_size

	while test_size == initial_size:
		test_data += b'A'
		encrypted_test_data = encryption_oracle.encrypt(test_data)
		test_size = len(encrypted_test_data)

	return test_size - initial_size


def detect_ecb_mode(encryption_oracle):
	'''
	This function detect if ECB mode is used
	The problem with ECB is that it is stateless and deterministic; 
	the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
	Due that, if we generate always the same data, the ecb mode will be always output
	the same ciphertext (except the random bytes added)
	'''
	data = bytes([0])*200
	encrypted_data = encryption_oracle.encrypt(data)
	encrypted_data_hex = hexlify(encrypted_data).decode('utf-8')
	
	blocks = [unhexlify(encrypted_data_hex[i:i + 32]) for i in range(0, len(encrypted_data_hex), 32)]
	numer_of_repeated_blocks = len(blocks) - len(set(blocks))

	return True if numer_of_repeated_blocks else False

def find_byte(encryption_oracle, block_size, known_bytes):
	prefix_length = block_size - ((1 + len(known_bytes)) % block_size) 
	prefix = bytes([0]*prefix_length)
	test_length = prefix_length + len(known_bytes) + 1
	real_ciphertext = encryption_oracle.encrypt(prefix)
	for i in range(256):
		test_ciphertext = encryption_oracle.encrypt(prefix + known_bytes + bytes([i]))
		if test_ciphertext[:test_length] == real_ciphertext[:test_length]:
			return bytes([i])
	return b''


if __name__ == '__main__':

	data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	encryption_oracle = encryption_oracle_ecb(data)

	block_size = discover_block_size(encryption_oracle)
	print("Block size:", block_size, "bytes")
	if not detect_ecb_mode(encryption_oracle):
		print("The cipher is NOT using ECB mode")
	else:
		print("The cipher is using ECB mode")

		decrypted_data = b''
		data_length = len(encryption_oracle.encrypt(b''))
		for i in range(data_length):
			next_byte = find_byte(encryption_oracle, block_size, decrypted_data)
			decrypted_data += next_byte
			#print(decrypted_data)
			print("Decrypting: " + "{:4.2f}".format(100*(i+1)/data_length) + "%", end='\r')
		print("Decryption complete!")
		print(decrypted_data.decode('utf-8'))