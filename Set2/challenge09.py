# Implement PKCS#7 padding

def pad_PKCS(text, l):
	pad = l - (len(text) % l)
	return text + bytes([pad]*pad)


if __name__ == '__main__':

	x = b"YELLOW SUBMARINE"
	y = pad_PKCS(x, 20)
	print(y)
