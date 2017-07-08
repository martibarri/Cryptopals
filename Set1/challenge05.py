# Implement repeating-key XOR
from binascii import hexlify

input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"
#input_string = input("Enter string: ")
#key = input("Enter key: ")

encrypted = ""
for i in range(int(len(input_string)/len(key)+1)):
	substring = input_string[i*len(key):(i+1)*len(key)]
	encrypted += "".join(chr(ord(x) ^ ord(y)) for x, y in zip(substring, key))
print(hexlify(encrypted.encode('utf-8')).decode('utf-8'))
