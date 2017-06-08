input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"
#input_string = raw_input("Enter string: ")
key = raw_input("Enter key: ")
hex_string = input_string.encode("hex")

encrypted = ""
for i in range(len(input_string)/len(key)+1):
	substring = input_string[i*len(key):(i+1)*len(key)]
	encrypted += "".join(chr(ord(x) ^ ord(y)) for x, y in zip(substring, key))
print encrypted.encode("hex")
