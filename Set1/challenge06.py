from operator import itemgetter
from binascii import hexlify
import base64

def XORcipher(string_ascii):
	english="ETAOINSHRDLU"
	english+=english.lower()
	english+=" "
	score_dict = {}
	decrypted_dict = {}
	for i in range(0,256):
		decrypted = []
		score = 0
		for x in range(len(string_ascii)):
			decrypted_char=chr(ord(string_ascii[x])^i)
			decrypted.append(decrypted_char)
			for a in range(len(english)): # more frequent characters in english
				if english[a]==decrypted_char:
					score+=1
			if ord(decrypted_char) < 32 or ord(decrypted_char)==127:
				score-=1
		score_dict[i] = score
		decrypted_dict[i] = ''.join(decrypted)
	key, value = max(score_dict.items(), key=lambda a:a[1])
	return {'key':key, 'decrypted': decrypted_dict[key]}

def hamming_distance(s1, s2):
	s1_bin = ''.join(format(ord(x), '08b') for x in s1)
	s2_bin = ''.join(format(ord(x), '08b') for x in s2)
	diffs = 0
	for ch1, ch2 in zip(s1_bin, s2_bin):
		if ch1 != ch2:
			diffs += 1
	return diffs

f = open('sources/6.txt', 'r')
encrypted_data_base64 = ""
for line in f :
	encrypted_data_base64 += line.strip('\n')
encrypted_data_ascii = base64.b64decode(encrypted_data_base64).decode('utf-8')

KEYSIZE_candidates = []
for KEYSIZE in range(2,41):
	differing1 = float(hamming_distance(encrypted_data_ascii[0:KEYSIZE], encrypted_data_ascii[KEYSIZE:KEYSIZE*2]))
	differing2 = float(hamming_distance(encrypted_data_ascii[KEYSIZE*2:KEYSIZE*3], encrypted_data_ascii[KEYSIZE*3:KEYSIZE*4]))
	value = ((differing1+differing2)/2)/KEYSIZE
	KEYSIZE_candidates.append({'KEYSIZE': KEYSIZE, 'value': value})

KEYSIZE_candidates = sorted(KEYSIZE_candidates, key=itemgetter('value'))

for i in range(10):
	ks = KEYSIZE_candidates[i]['KEYSIZE']
	print("-"*100)
	print("KEYSIZE:", ks)
	blocks = []
	tblocks = [""]*ks
	key = ""
	decrypted = [""]*len(encrypted_data_ascii)
	for j in range(int(len(encrypted_data_ascii)/ks)):
		blocks.append(encrypted_data_ascii[ks*j:ks*(j+1)])
	for k in range(ks):
		for l in range(len(blocks)):
			tblocks[k] += blocks[l][k]
		result = XORcipher(tblocks[k])
		subkey = result['key']
		tdecrypted = result['decrypted']
		key += chr(subkey)
		for m in range(len(tdecrypted)):
			decrypted[k+m*ks] = tdecrypted[m]
	print("KEY:", key)
	print("OUTPUT:",''.join(decrypted))
