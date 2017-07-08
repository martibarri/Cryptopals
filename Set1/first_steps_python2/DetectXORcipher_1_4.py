import operator
import XORcipher_1_3 as XOR

f = open('4.txt', 'r')

for line in f:
	#print line.strip('\n')
	results=XOR.XORcipher(line.strip('\n'))
	for key, value in results.items():
		print key, "-", chr(key), "-", value

