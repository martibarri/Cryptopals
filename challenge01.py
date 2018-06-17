from binascii import unhexlify, b2a_base64

input_hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"


def hex2base64(input_hex=input_hex_string):
    return b2a_base64(unhexlify(input_hex)).decode('utf-8')


if __name__ == '__main__':
    resultBase64 = hex2base64(input_hex_string)
    if resultBase64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n":
        print("result true")
