# Detect AES in ECB mode

f = open('../sources/8.txt', 'r')
encrypted_data_hex = []
for line in f:
	encrypted_data_hex.append(line.strip('\n'))

scores = []

for i in range(len(encrypted_data_hex)):
	blocks = [encrypted_data_hex[i][j:j + 32] for j in range(0, len(encrypted_data_hex[i]), 32)]
	score = len(blocks) - len(set(blocks))
	scores.append(score)

max_score = max(scores)
positions = [i for i, j in enumerate(scores) if j == max_score] 
# note that in fact only one score != 0
for i in range(len(positions)):
	print("Ciphertext encrypted with AES-ECB:")
	print([encrypted_data_hex[positions[i]][j:j + 32] for j in range(0, len(encrypted_data_hex[positions[i]]), 32)])
	print("Position:", positions[i])
	print("Number of repeated blocks:", scores[positions[i]])
