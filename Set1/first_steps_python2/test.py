# Challenge 4
print '\n'
print 'Challenge 4'

f = open('4.txt', 'r')
lines = f.readlines()

a = 'ETAOINSHRDLU'
b = a.lower()
c = ' '
english = ''.join([a,c,b])

# Store in an array named encrypted, 
# all the strings off the file
encrypted = []
for x in range(len(lines)):
  encrypted.append(lines[x].strip('\n'))


score_dict = {}
decrypted_dict = {}

# Iterate over encrypted
for y in range(len(encrypted)):
  # Get the first 
  print encrypted[y]
  decoded_encrypted = encrypted[y].decode("hex")
  print decoded_encrypted
  # Try all the ascii bits
  for j in range(0,255):
    output = []
    score = 0

    # XOR every char in the decoded string
    # with the ascii value3
    for i in range(len(decoded_encrypted)):
      c = chr(ord(decoded_encrypted[i])^j)
      output.append(c)

      for x in range(len(english)):
        if english[x] == c:
          score += 1

    string_output = ''.join(output)
    score_dict[j] = score
    decrypted_dict[j] = string_output

  key, value = max(score_dict.iteritems(), key=lambda x:x[1])

  print ("Index %s, encrypted string %s, char %s, score %s and output: %s" 
         % (y, chr(key), encrypted[y], score_dict[key], decrypted_dict[key]))
