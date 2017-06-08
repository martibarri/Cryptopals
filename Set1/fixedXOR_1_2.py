#  Write a function that takes two equal-length buffers and produces their XOR combination.
string1_hex = raw_input("Enter hex string1: ")
string2_hex = raw_input("Enter hex string2: ")
string1_dec = string1_hex.decode("hex")
string2_dec = string2_hex.decode("hex")
print("string1_dec: " + string1_dec)
print("string2_dec: " + string2_dec)

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

xored_dec = xor_strings(string1_dec, string2_dec)
xored_hex = xored_dec.encode("hex")
print("xored_dec: " + xored_dec)
print("xored_hex: " + xored_hex)
	
	

