# Implement PKCS#7 padding

def pad_PKCS(text, l):
	pad = l-len(text)
	if pad > 0:
		return text + bytes([pad]*pad)
	return text

x = b"YELLOW SUBMARINE"
y = pad_PKCS(x, 20)
print(y)
