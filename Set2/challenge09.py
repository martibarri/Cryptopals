# Implement PKCS#7 padding

def pad_PKCS(text, l):
	pad = (l - (len(text) % l)) % l
	return text + bytes([pad]*pad) if len(text) != 0 else bytes([l]*l)


if __name__ == '__main__':

	x = b"YELLOW SUBMARINE"
	y = pad_PKCS(x, 20)
	print(y)
