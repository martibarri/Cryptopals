def validate_pad_PKCS(text, l):
    pad = text[-1]
    if len(text) % l == 0:  # padding
        # validate PKCS#7 padding
        for i in range(len(text)):
            if text[i] < l:  # detect some sort of padding
                padding_length = len(text[i:])
                for j in range(padding_length):
                    if text[i + j] != padding_length:
                        raise Exception("wrong padding!")
                return text[0:len(text) - pad]  # unpadding
        return text  # no padding
    else:  # no padding
        return text


if __name__ == '__main__':
    x1 = b"ICE ICE BABY\x04\x04\x04\x04"
    print(x1)
    print(validate_pad_PKCS(x1, 16))
    # x2 = b"ICE ICE BABY\x01\x02\x03\x04"
    x2 = b"ICE ICE BABY\x05\x05\x05\x05"
    print(x2)
    print(validate_pad_PKCS(x2, 16))
