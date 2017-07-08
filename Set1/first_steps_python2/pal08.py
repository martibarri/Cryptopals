import base64
from Crypto.Cipher import AES

#f = base64.b64decode(open('8.txt', 'r').read())
f = open('8.txt', 'r')

encrypted_data_base64 = ""

#key = b"YELLOW SUBMARINE"
#cipher = AES.new(key, AES.MODE_ECB)
#decrypted = cipher.decrypt(f)
#print(decrypted)

for line in f :
	print line
	print len(line)
	print base64.b64decode(line)
	#encrypted_data_base64 += line.strip('\n')

# encrypted_data_ascii = encrypted_data_base64.decode("base64")
# 	print encrypted_data_base64
