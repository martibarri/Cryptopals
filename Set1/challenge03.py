import operator
from binascii import unhexlify, hexlify
# The hex encoded string has been XOR'd against a single character. Find the key, decrypt the message. 
string_hex1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def XORcipher(string_hex):
	string_dec = unhexlify(string_hex).decode('utf-8')
	english="ETAOINSHRDLU"
	english+=english.lower()
	score = [-1]*256
	decrypted_array = [""]*256
	dict = {}
	for i in range(0,256):
		decrypted = ""
		for x in string_dec:
			decrypted+=chr(ord(x)^i)
		# print(i, chr(i), decrypted)
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
	#print sorted_score
	#print "max score:", sorted_score[255][1]
	result = {}
	for j in range(246, 256):
		#print sorted_score[j][0]
		#print decrypted_array[sorted_score[j][0]]
		if sorted_score[j][1] > 40: # parameter to avoid non legible characters (negative score)
			#print sorted_score[j][0], "- score:", sorted_score[j][1]
			result[sorted_score[j][0]]=decrypted_array[sorted_score[j][0]]
		#print sorted_score[j][0], "-", chr(sorted_score[j][0]), ":",decrypted_array[sorted_score[j][0]]
	return result


a = XORcipher(string_hex1)
print("------ key -", "char", "- decrypted string ------")
for key, value in a.items():
	print(key, "-", chr(key), "-", value)
