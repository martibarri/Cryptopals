import operator

# One of the 60-character strings in the file has been encrypted by single-character XOR. 

def XORcipher(string_hex):
	string_dec = (''.join([chr(int(''.join(c), 16)) for c in zip(string_hex[0::2], string_hex[1::2])]))
	english="ETAOINSHRDLU"
	english+=english.lower()
	score = [-1]*256
	decrypted_array = [""]*256
	dict = {}
	for i in range(0,256):
		decrypted = ""
		for x in string_dec:
			decrypted+=chr(ord(x)^i)
		for a in english: # more frequent characters in english
			if decrypted.find(a)!=-1: 
				score[i]+=2
		for b in range(0, 31): # non legible characters
			if decrypted.find(chr(b))!=-1: 
				score[i]-=50
		if decrypted.find(chr(127))!=-1: # DEL
			score[i]-=50
		for c in range(65, 90): # uppercase letter
			if decrypted.find(chr(c))!=-1: 
				score[i]+=3
		for d in range(97, 122): # lowercase letter
			if decrypted.find(chr(d))!=-1: 
				score[i]+=3
		if decrypted.find(chr(32))!=-1: # space
			score[i]+=20
		for e in range(128, 256):
			if decrypted.find(chr(e))!=-1: 
				score[i]-=50
		dict[i]=score[i]
		decrypted_array[i]=decrypted
	sorted_score = sorted(dict.items(), key=operator.itemgetter(1))
	result = {}
	for j in range(246, 256):
		if sorted_score[j][1] > 40: # parameter to avoid non legible characters (negative score)
			result[sorted_score[j][0]]=decrypted_array[sorted_score[j][0]]
	return result

f = open('../sources/4.txt', 'r')

for line in f:
	results=XORcipher(line.strip('\n'))
	for key, value in results.items():
		print(line.strip('\n'))
		print(key, "-", chr(key), "-", value)
