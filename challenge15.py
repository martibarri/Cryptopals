from utils import validate_pad_pkcs


if __name__ == '__main__':
    x1 = b"ICE ICE BABY\x04\x04\x04\x04"
    print("x1:", x1)
    try:
        print("good padding:", validate_pad_pkcs(x1))
    except ValueError:
        print("bad padding")
        pass

    x2 = b"ICE ICE BABY\x01\x02\x03\x04"
    print("x2:", x2)
    try:
        print("good padding:", validate_pad_pkcs(x2))
    except ValueError:
        print("bad padding")
        pass

    x3 = b"ICE ICE BABY\x05\x05\x05\x05"
    print("x3:", x3)
    try:
        print("good padding:", validate_pad_pkcs(x3))
    except ValueError:
        print("bad padding")
        pass
