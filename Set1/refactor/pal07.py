import base64
from Crypto.Cipher import AES

f = base64.b64decode(open('7.txt', 'r').read())

key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(f)
print(decrypted)