from binascii import unhexlify, b2a_base64

hex_string = input("Enter HEX string to convert to BASE64:")
result = b2a_base64(unhexlify(hex_string)).decode('utf-8')
print(result)