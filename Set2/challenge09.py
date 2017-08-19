# Implement PKCS#7 padding

def pad_PKCS(text, l):
	pad = (l - (len(text) % l)) % l
	if len(text) != 0: 
		return text + bytes([pad]*pad) 
	else: 
		return bytes([l]*l)


if __name__ == '__main__':

	x = b"YELLOW SUBMARINE"
	y = pad_PKCS(x, 20)
	print(y)
