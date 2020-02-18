from challenges.utils import hex2base64, base642hex


hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
hex_bytes = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64_string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n'
b64_bytes = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n'


def test_hex2base64_string_string():
    assert hex2base64(input_hex=hex_string, bytes_out=False) == b64_string


def test_hex2base64_string_bytes():
    assert hex2base64(input_hex=hex_string, bytes_out=True) == b64_bytes


def test_hex2base64_bytes_string():
    assert hex2base64(input_hex=hex_bytes, bytes_out=False) == b64_string


def test_hex2base64_bytes_bytes():
    assert hex2base64(input_hex=hex_bytes, bytes_out=True) == b64_bytes


def test_base642hex_string_string():
    assert base642hex(input_base64=b64_string, bytes_out=False) == hex_string


def test_base642hex_string_bytes():
    assert base642hex(input_base64=b64_string, bytes_out=True) == hex_bytes


def test_base642hex_bytes_string():
    assert base642hex(input_base64=b64_bytes, bytes_out=False) == hex_string


def test_base642hex_bytes_bytes():
    assert base642hex(input_base64=b64_bytes, bytes_out=True) == hex_bytes
