hex = raw_input("Enter HEX string to convert to BASE64:")
base64 = hex.decode("hex").encode("base64")
print(base64)
