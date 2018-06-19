# Implement PKCS#7 padding
from utils import pad_pkcs

if __name__ == '__main__':
    x = b"YELLOW SUBMARINE"
    y = pad_pkcs(x, 20)
    print(y)
