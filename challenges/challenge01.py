from utils import hex2base64
from huepy import good, bad

if __name__ == '__main__':

    input_hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

    resultBase64 = hex2base64(input_hex_string, bytes_out=False)

    if resultBase64 == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n':
        print(good('result true'))
    else:
        print(bad('keep trying...'))
